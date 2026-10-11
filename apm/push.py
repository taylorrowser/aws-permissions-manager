"""Web Push (RFC 8291 aes128gcm payloads, RFC 8292 VAPID) using only `cryptography`.
Works with iOS home-screen web apps, Safari, Chrome and Firefox."""
import base64
import json
import os
import struct
import time
from concurrent.futures import ThreadPoolExecutor, wait
import urllib.error
import urllib.request
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def generate_vapid_keys():
    """(private PEM, public key as base64url uncompressed point for the browser)."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pem.decode(), b64url(_raw_public(key))


def _hkdf(salt, ikm, info, length):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def encrypt(payload, p256dh, auth):
    ua_public = unb64url(p256dh)
    auth_secret = unb64url(auth)
    as_key = ec.generate_private_key(ec.SECP256R1())
    as_public = _raw_public(as_key)
    shared = as_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public))
    ikm = _hkdf(auth_secret, shared, b"WebPush: info\x00" + ua_public + as_public, 32)
    salt = os.urandom(16)
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    body = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)
    return salt + struct.pack("!IB", 4096, len(as_public)) + as_public + body


def vapid_header(endpoint, private_pem, subject):
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    u = urlparse(endpoint)
    header = b64url(json.dumps({"typ": "JWT", "alg": "ES256"}).encode())
    claims = b64url(json.dumps({"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + 12 * 3600,
                                "sub": subject}).encode())
    r, s = decode_dss_signature(key.sign(f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256())))
    jwt = f"{header}.{claims}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
    return f"vapid t={jwt}, k={b64url(_raw_public(key))}"


def send(subscription, message, private_pem, subject, ttl=86400, timeout=10):
    """POST one notification. Returns the HTTP status; 404/410 mean the subscription is gone."""
    endpoint = subscription["endpoint"]
    body = encrypt(json.dumps(message).encode(), subscription["keys"]["p256dh"], subscription["keys"]["auth"])
    req = urllib.request.Request(endpoint, data=body, method="POST", headers={
        "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", "TTL": str(ttl),
        "Urgency": "high", "Authorization": vapid_header(endpoint, private_pem, subject)})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        reason = e.read()[:200].decode(errors="replace")
        print(json.dumps({"event": "push_rejected", "service": urlparse(endpoint).netloc, "status": e.code, "reason": reason}))
        return e.code


GONE = (404, 410)
RETRYABLE = (429, 500, 502, 503, 504)


def deliver(subscriptions, message, private_pem, subject, ttl=86400, budget=10):
    """Send to every subscription in parallel, retrying a transient failure once. The Lambda is
    frozen once it responds, so this runs inline, and the whole send returns within about
    `budget` seconds whatever the push services do; a send still running then counts as failed.
    Returns {pk: (outcome, status)}, outcome being delivered, gone or failed; status is the HTTP
    status, or None for a network error or timeout."""
    deadline = time.monotonic() + budget

    def one(s):
        status = None
        if time.monotonic() >= deadline:  # queued behind slow sends past the budget
            return "failed", None
        for attempt in (1, 2):
            try:
                status = send(s["sub"], message, private_pem, subject, ttl=ttl, timeout=4)
            except Exception as e:  # DNS, TLS, timeout, bad stored subscription
                print(json.dumps({"event": "push_error", "device": s["pk"][4:16], "error": str(e)[:200]}))
                status = None
            if status is not None and status < 300:
                return "delivered", status
            if status in GONE:
                return "gone", status
            if attempt == 1 and (status is None or status in RETRYABLE) and time.monotonic() + 5 < deadline:
                time.sleep(0.5)
                continue
            return "failed", status
        return "failed", status

    if not subscriptions:
        return {}
    pool = ThreadPoolExecutor(max_workers=min(16, len(subscriptions)))
    futures = {s["pk"]: pool.submit(one, s) for s in subscriptions}
    wait(futures.values(), timeout=max(0, deadline - time.monotonic()))
    pool.shutdown(wait=False, cancel_futures=True)  # don't hold the response for a hung send
    # Cancelled futures also count as done, but have no result.
    return {pk: f.result() if f.done() and not f.cancelled() else ("failed", None) for pk, f in futures.items()}
