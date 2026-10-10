"""NON-LIVE, coordinator-authorized, proof-of-possession run enrollment.

This is key possession plus explicitly configured coordinator authority, NOT
machine attestation, unique-computer identity or an unsigned thread-ID assertion.
No provider trust, account identifiers, network adapter or connection enrollment
is supplied. ``configured=True, offline_mode=True`` and exact StandingTrust
records are necessary even for local integration use. Production is refused.

ES256 signatures are verified by PyJWT/cryptography. The proof format uses
RFC 9449 section 4 (typ/alg/jwk; htm/htu/iat/jti/nonce), with application-specific
``body_digest``, ``binding_hash`` and ``enrollment_id`` or ``run_id`` claims.
This is an EXPERIMENTAL DPoP-shaped application profile, NOT a complete or
compliant OAuth/DPoP implementation or an OAuth authorization/token service.
There is no access token to hash in ``ath``: run IDs are non-secret locators,
and every privileged use additionally requires a fresh signed proof. If a
future transport also uses an OAuth access token, it MUST add/check ``ath``.
Thumbprints use RFC 7638's canonical EC members and SHA-256.
https://www.rfc-editor.org/rfc/rfc9449 (checked 2026-10-07)
https://www.rfc-editor.org/rfc/rfc7638 (checked 2026-10-07)

Use trusted configured origin/path for htu, never caller-supplied URLs or
untrusted forwarding headers. The route must compute body_digest from the canonical exact request body;
this application profile signs that digest because DPoP does not inherently
sign request bodies. Grant/lease identifiers still need server authorization.

SQLite persists one-time enrollments, nonces, replay IDs and revocations across
process restarts. Use the SAME SQLite database as the offline grant service if
its active_grant callback reads SQLite: BEGIN IMMEDIATE then serializes grant
changes with proof validation. This is not distributed production fencing.
Issuance must recheck current grant/run authorization at the credential boundary.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from .auth import AuthError, AuthUnconfigured, AuthConfigurationError, Principal


class EnrollmentDenied(AuthError):
    pass


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


EMPTY_BODY_DIGEST = _hash(_json({}))


def _id(value) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9_:.@/-]{1,256}', value))


def _nonce(value) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{32,128}', value))


def _public_key(jwk: Mapping) -> tuple[dict, str, object]:
    try:
        if (not isinstance(jwk, dict) or jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256'
                or 'd' in jwk or jwk.get('alg', 'ES256') != 'ES256'
                or jwk.get('use', 'sig') != 'sig'
                or ('key_ops' in jwk and jwk['key_ops'] != ['verify'])
                or any(not isinstance(jwk.get(k), str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', jwk[k]) for k in ('x', 'y'))):
            raise ValueError()
        public = {k: jwk[k] for k in ('crv', 'kty', 'x', 'y')}
        key = jwt.PyJWK.from_dict(public, algorithm='ES256').key
        # Reject noncanonical encodings; RFC 7638 hashes representations, not points.
        canonical = jwt.algorithms.ECAlgorithm.to_jwk(key, as_dict=True)
        if any(public[k] != canonical[k] for k in public):
            raise ValueError()
        thumbprint = base64.urlsafe_b64encode(hashlib.sha256(_json(public).encode()).digest()).rstrip(b'=').decode()
        return public, thumbprint, key
    except Exception:
        raise EnrollmentDenied('invalid public proof key') from None


def jwk_thumbprint(public_jwk: dict) -> str:
    """RFC 7638 SHA-256 EC public-key thumbprint; no private key is accepted."""
    return _public_key(public_jwk)[1]


def _binding(value: dict) -> dict:
    if (not isinstance(value, dict)
            or set(value) != {'grant_id', 'revision', 'digest', 'roles', 'not_after'}
            or not _id(value['grant_id']) or type(value['revision']) is not int or value['revision'] < 1
            or not isinstance(value['digest'], str) or not re.fullmatch(r'[0-9a-f]{64}', value['digest'])
            or not isinstance(value['roles'], (list, tuple)) or not 1 <= len(value['roles']) <= 20
            or any(not _id(role) for role in value['roles'])
            or len(set(value['roles'])) != len(value['roles'])
            or (value['not_after'] is not None and type(value['not_after']) is not int)):
        raise EnrollmentDenied('invalid exact grant binding')
    return {**value, 'roles': sorted(value['roles'])}


def binding_hash(grant_binding: dict) -> str:
    """Hash of the exact canonical grant binding used in proof extension claims."""
    return _hash(_json(_binding(grant_binding)))


def _htu(value: str, offline: bool) -> str:
    try:
        if not isinstance(value, str) or len(value) > 2048 or '\\' in value or any(c.isspace() for c in value):
            raise ValueError()
        url = urlsplit(value)
        url.port
        if (not url.hostname or url.username or url.password or '*' in value
                or (url.scheme != 'https' and not (offline and url.scheme == 'http'
                    and url.hostname in {'localhost', '127.0.0.1', '::1'}))):
            raise ValueError()
        # RFC 9449 excludes query and fragment. Routes must validate body/query too.
        return urlunsplit((url.scheme, url.netloc, url.path or '/', '', ''))
    except Exception:
        raise EnrollmentDenied('invalid proof endpoint') from None


def fresh_key() -> tuple[ec.EllipticCurvePrivateKey, dict]:
    """Fresh in-memory P-256 key; never writes, exports or logs private key bytes.

    The private cryptography object has a non-secret object repr. Secure storage
    and renewal across worker restarts are separate, unimplemented boundaries.
    """
    private = ec.generate_private_key(ec.SECP256R1())
    public = jwt.algorithms.ECAlgorithm.to_jwk(private.public_key(), as_dict=True)
    return private, _public_key(public)[0]


def make_proof(private_key: ec.EllipticCurvePrivateKey, public_jwk: dict,
               method: str, url: str, nonce: str, grant_binding: dict, *,
               enrollment_id: str | None = None, run_id: str | None = None,
               body_digest: str = EMPTY_BODY_DIGEST,
               clock: Callable[[], float] = time.time, offline_mode: bool = False) -> str:
    """Sign the documented ES256 DPoP application profile, without persisting keys.

    Production HTTP transport is not implemented here. HTTP loopback proof URLs
    require explicit offline_mode; ordinary proof URLs must use HTTPS.
    """
    try:
        if (not isinstance(private_key, ec.EllipticCurvePrivateKey)
                or not isinstance(private_key.curve, ec.SECP256R1)
                or bool(enrollment_id) == bool(run_id)
                or not _id(enrollment_id or run_id)
                or not isinstance(method, str) or not re.fullmatch(r'[A-Z]{3,12}', method)
                or not _nonce(nonce) or not isinstance(body_digest, str)
                or not re.fullmatch(r'[0-9a-f]{64}', body_digest)):
            raise ValueError()
        public, thumbprint, _ = _public_key(public_jwk)
        actual_public = jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
        if not hmac.compare_digest(thumbprint, jwk_thumbprint(actual_public)):
            raise ValueError()
        claims = {'htm': method, 'htu': _htu(url, offline_mode), 'iat': int(clock()),
                  'jti': secrets.token_hex(16), 'nonce': nonce,
                  'binding_hash': binding_hash(grant_binding), 'body_digest': body_digest}
        claims['enrollment_id' if enrollment_id else 'run_id'] = enrollment_id or run_id
        return jwt.encode(claims, private_key, algorithm='ES256',
                          headers={'typ': 'dpop+jwt', 'jwk': public})
    except Exception:
        raise EnrollmentDenied('cannot create key-bound request proof') from None


@dataclass(frozen=True)
class StandingTrust:
    owner_id: str
    subject: str
    client_id: str
    authentication_id: str
    connection_id: str
    max_lifetime: int = 3600

    def __post_init__(self):
        if (any(not _id(x) for x in (self.owner_id, self.subject, self.client_id,
                                    self.authentication_id, self.connection_id))
                or type(self.max_lifetime) is not int or not 1 <= self.max_lifetime <= 86400):
            raise AuthConfigurationError('invalid explicit coordinator trust')


class CoordinatorEnrollment:
    name = 'offline-coordinator-key-bound'

    def __init__(self, path, *, configured: bool = False, offline_mode: bool = False,
                 trust: tuple[StandingTrust, ...] = (),
                 active_grant: Callable[[str], dict] | None = None,
                 redeem_url: str | None = None, clock: Callable[[], float] = time.time,
                 proof_ttl: int = 60, challenge_ttl: int = 120):
        if configured and not offline_mode:
            raise AuthUnconfigured('production coordinator enrollment is not implemented')
        if (type(proof_ttl) is not int or not 1 <= proof_ttl <= 120
                or type(challenge_ttl) is not int or not 1 <= challenge_ttl <= 300):
            raise AuthConfigurationError('invalid proof lifetime')
        self.path = str(path)
        self.configured, self.offline_mode = configured, offline_mode
        self.trust, self.active_grant = tuple(trust), active_grant
        self.redeem_url, self.clock = redeem_url, clock
        self.proof_ttl, self.challenge_ttl = proof_ttl, challenge_ttl
        if configured:
            if not self.trust or any(not isinstance(t, StandingTrust) for t in self.trust) or not callable(active_grant) or not redeem_url:
                raise AuthUnconfigured('explicit coordinator trust and active grant adapter required')
            identities = [(t.owner_id, t.subject, t.client_id, t.authentication_id) for t in self.trust]
            if len(set(identities)) != len(identities):
                raise AuthConfigurationError('ambiguous coordinator trust')
            self.redeem_url = _htu(redeem_url, offline_mode)
            self._initialize()

    def _ready(self):
        if not self.configured:
            raise AuthUnconfigured('coordinator enrollment trust is not configured')

    def _initialize(self):
        with self._tx() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS coordinator_enrollments(
              id TEXT PRIMARY KEY,actor TEXT NOT NULL,idempotency_key TEXT NOT NULL,
              payload_hash TEXT NOT NULL,owner TEXT NOT NULL,subject TEXT NOT NULL,
              client TEXT NOT NULL,authentication TEXT NOT NULL,connection TEXT NOT NULL,
              public_jwk TEXT NOT NULL,thumbprint TEXT NOT NULL,binding TEXT NOT NULL,
              challenge TEXT NOT NULL,challenge_expires INTEGER NOT NULL,
              run_expires INTEGER NOT NULL,max_expires INTEGER NOT NULL,state TEXT NOT NULL,created INTEGER NOT NULL,
              UNIQUE(actor,idempotency_key));
            CREATE TABLE IF NOT EXISTS coordinator_runs(
              id TEXT PRIMARY KEY,enrollment TEXT NOT NULL UNIQUE,owner TEXT NOT NULL,
              subject TEXT NOT NULL,client TEXT NOT NULL,authentication TEXT NOT NULL,
              connection TEXT NOT NULL,public_jwk TEXT NOT NULL,thumbprint TEXT NOT NULL,
              binding TEXT NOT NULL,expires INTEGER NOT NULL,max_expires INTEGER NOT NULL,
              state TEXT NOT NULL,created INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS coordinator_nonces(
              hash TEXT PRIMARY KEY,run_id TEXT NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS coordinator_replays(
              thumbprint TEXT NOT NULL,jti TEXT NOT NULL,expires INTEGER NOT NULL,
              PRIMARY KEY(thumbprint,jti));
            CREATE TABLE IF NOT EXISTS coordinator_revoked_connections(
              connection TEXT PRIMARY KEY,revoked_at INTEGER NOT NULL);
            ''')

    @contextmanager
    def _tx(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @contextmanager
    def _read(self):
        db = sqlite3.connect('file:' + self.path + '?mode=ro', uri=True)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA query_only=ON')
            yield db
        finally:
            db.close()

    def _now(self) -> int:
        return int(self.clock())

    def _trust(self, principal: Principal) -> StandingTrust:
        if not isinstance(principal, Principal) or principal.actor_kind not in {'bearer_user', 'machine'}:
            raise EnrollmentDenied('trusted coordinator authentication required')
        for trust in self.trust:
            if ((principal.owner_id, principal.subject, principal.client_id, principal.authentication_id)
                    == (trust.owner_id, trust.subject, trust.client_id, trust.authentication_id)):
                return trust
        raise EnrollmentDenied('trusted coordinator authentication required')

    def _connection(self, db, connection: str):
        if db.execute('SELECT 1 FROM coordinator_revoked_connections WHERE connection=?', (connection,)).fetchone():
            raise EnrollmentDenied('coordinator connection is revoked')

    def _current(self, expected: dict, owner: str, subject: str, client: str) -> dict:
        try:
            current = self.active_grant(expected['grant_id'])
            if not isinstance(current, dict) or current.get('state') != 'active':
                raise ValueError()
            if (current.get('owner_id'), current.get('subject'), current.get('client_id')) != (owner, subject, client):
                raise ValueError()
            binding = _binding({k: v for k, v in current.items() if k not in {'state', 'owner_id', 'subject', 'client_id'}})
            if binding != expected or (binding['not_after'] is not None and binding['not_after'] <= self._now()):
                raise ValueError()
            return binding
        except Exception:
            raise EnrollmentDenied('exact grant is no longer active') from None

    def _trusted_row(self, row):
        # Removing configured trust invalidates prior runs, including after restart.
        for trust in self.trust:
            if ((row['owner'], row['subject'], row['client'], row['authentication'], row['connection']) ==
                    (trust.owner_id, trust.subject, trust.client_id, trust.authentication_id, trust.connection_id)):
                if row['max_expires'] > row['created'] + trust.max_lifetime:
                    raise EnrollmentDenied('coordinator lifetime authority was narrowed')
                return trust
        raise EnrollmentDenied('coordinator trust is no longer configured')

    def _prepared(self, row) -> dict:
        binding = json.loads(row['binding'])
        return {'enrollment_id': row['id'], 'challenge': row['challenge'],
                'expires_at': row['challenge_expires'], 'redeem_url': self.redeem_url,
                'authority': {'owner_id': row['owner'], 'subject': row['subject'],
                              'client_id': row['client'], 'connection_id': row['connection'],
                              'key_thumbprint': row['thumbprint'], 'grant_binding': binding,
                              'binding_hash': binding_hash(binding),
                              'run_expires_at': row['run_expires'], 'maximum_expires_at': row['max_expires']},
                'mode': self.name, 'machine_attestation': False}

    def prepare(self, principal: Principal, public_jwk: dict, grant_binding: dict,
                lifetime: int, idempotency_key: str) -> dict:
        self._ready()
        trust = self._trust(principal)
        if (type(lifetime) is not int or not 1 <= lifetime <= trust.max_lifetime
                or not isinstance(idempotency_key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,80}', idempotency_key)):
            raise EnrollmentDenied('invalid enrollment lifetime or idempotency key')
        public, thumbprint, _ = _public_key(public_jwk)
        binding = _binding(grant_binding)
        actor = _hash(_json([trust.owner_id, trust.subject, trust.client_id, trust.authentication_id, trust.connection_id]))
        payload = _hash(_json({'key': thumbprint, 'binding': binding, 'lifetime': lifetime}))
        with self._tx() as db:
            self._connection(db, trust.connection_id)
            self._current(binding, trust.owner_id, trust.subject, trust.client_id)
            old = db.execute('SELECT * FROM coordinator_enrollments WHERE actor=? AND idempotency_key=?', (actor, idempotency_key)).fetchone()
            if old:
                if not hmac.compare_digest(old['payload_hash'], payload):
                    raise EnrollmentDenied('idempotency key payload conflict')
                if old['state'] != 'prepared' or old['challenge_expires'] <= self._now():
                    raise EnrollmentDenied('enrollment is expired or consumed')
                return self._prepared(old)
            now = self._now()
            maximum = min(now + trust.max_lifetime, binding['not_after'] or now + trust.max_lifetime)
            expires = now + lifetime
            if expires > maximum:
                raise EnrollmentDenied('run lifetime exceeds exact grant cutoff')
            enrollment_id, challenge = 'enr_' + secrets.token_hex(16), secrets.token_urlsafe(32)
            db.execute('INSERT INTO coordinator_enrollments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (enrollment_id, actor, idempotency_key, payload, trust.owner_id, trust.subject,
                 trust.client_id, trust.authentication_id, trust.connection_id, _json(public), thumbprint,
                 _json(binding), challenge, min(now + self.challenge_ttl, expires), expires, maximum, 'prepared', now))
            return self._prepared(db.execute('SELECT * FROM coordinator_enrollments WHERE id=?', (enrollment_id,)).fetchone())

    def _proof(self, proof: str, public_jwk: dict, method: str, url: str,
               nonce: str, binding: dict, subject_claim: str, subject_id: str, body_digest: str) -> dict:
        try:
            if not isinstance(proof, str) or not 1 <= len(proof) <= 8192:
                raise ValueError()
            if not isinstance(method, str) or not re.fullmatch(r'[A-Z]{3,12}', method) or not _nonce(nonce):
                raise ValueError()
            header = jwt.get_unverified_header(proof)
            if (header.get('typ') != 'dpop+jwt' or header.get('alg') != 'ES256'
                    or any(k in header for k in ('jku', 'x5u', 'crit', 'kid'))):
                raise ValueError()
            _, thumbprint, key = _public_key(public_jwk)
            if not hmac.compare_digest(_public_key(header.get('jwk'))[1], thumbprint):
                raise ValueError()
            claims = jwt.decode(proof, key, algorithms=['ES256'],
                options={'require': ['htm', 'htu', 'iat', 'jti', 'nonce', 'binding_hash', 'body_digest', subject_claim],
                         'verify_aud': False, 'verify_exp': False, 'verify_iat': False, 'verify_nbf': False})
            now = self._now()
            if (claims['htm'] != method or claims['htu'] != _htu(url, self.offline_mode)
                    or type(claims['iat']) is not int or not now - self.proof_ttl <= claims['iat'] <= now
                    or not _id(claims['jti']) or not _nonce(claims['nonce'])
                    or not hmac.compare_digest(claims['nonce'], nonce)
                    or claims['binding_hash'] != binding_hash(binding)
                    or not isinstance(body_digest, str) or not re.fullmatch(r'[0-9a-f]{64}', body_digest)
                    or claims['body_digest'] != body_digest
                    or claims[subject_claim] != subject_id):
                raise ValueError()
            return claims
        except Exception:
            raise EnrollmentDenied('invalid key-bound request proof') from None

    def _record_proof(self, db, thumbprint: str, claims: dict):
        try:
            db.execute('INSERT INTO coordinator_replays VALUES (?,?,?)',
                       (thumbprint, claims['jti'], self._now() + self.proof_ttl))
        except sqlite3.IntegrityError:
            raise EnrollmentDenied('request proof has already been used') from None

    def _new_nonce(self, db, run_id: str, expires: int) -> str:
        nonce = secrets.token_urlsafe(32)
        db.execute('INSERT INTO coordinator_nonces VALUES (?,?,?,0)',
                   (_hash(nonce), run_id, min(expires, self._now() + self.proof_ttl)))
        return nonce

    def _run_summary(self, row) -> dict:
        binding = json.loads(row['binding'])
        return {'run_id': row['id'], 'owner_id': row['owner'], 'subject': row['subject'],
                'client_id': row['client'], 'authentication_id': row['authentication'],
                'connection_id': row['connection'], 'key_thumbprint': row['thumbprint'],
                'grant_id': binding['grant_id'], 'grant_binding': binding,
                'binding_hash': binding_hash(binding), 'expires_at': row['expires'],
                'maximum_expires_at': row['max_expires'], 'state': row['state'],
                'mode': self.name, 'machine_attestation': False}

    def redeem(self, enrollment_id: str, proof: str, method: str = 'POST', url: str | None = None,
               *, body_digest: str = EMPTY_BODY_DIGEST) -> dict:
        self._ready()
        if method != 'POST' or _htu(url or self.redeem_url, self.offline_mode) != self.redeem_url:
            raise EnrollmentDenied('invalid enrollment redemption endpoint')
        with self._tx() as db:
            row = db.execute('SELECT * FROM coordinator_enrollments WHERE id=?', (enrollment_id,)).fetchone()
            if not row or row['state'] != 'prepared' or row['challenge_expires'] <= self._now():
                raise EnrollmentDenied('enrollment is expired or consumed')
            self._trusted_row(row)
            self._connection(db, row['connection'])
            binding = json.loads(row['binding'])
            self._current(binding, row['owner'], row['subject'], row['client'])
            claims = self._proof(proof, json.loads(row['public_jwk']), method, self.redeem_url,
                                 row['challenge'], binding, 'enrollment_id', enrollment_id, body_digest)
            self._record_proof(db, row['thumbprint'], claims)
            run_id = 'run_' + secrets.token_hex(16)
            db.execute("UPDATE coordinator_enrollments SET state='consumed' WHERE id=?", (enrollment_id,))
            db.execute('INSERT INTO coordinator_runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (run_id, row['id'], row['owner'], row['subject'], row['client'], row['authentication'],
                 row['connection'], row['public_jwk'], row['thumbprint'], row['binding'],
                 row['run_expires'], row['max_expires'], 'active', row['created']))
            run = db.execute('SELECT * FROM coordinator_runs WHERE id=?', (run_id,)).fetchone()
            return {**self._run_summary(run), 'nonce': self._new_nonce(db, run_id, run['expires'])}

    def _run(self, db, run_id: str, binding: dict | None = None):
        row = db.execute('SELECT * FROM coordinator_runs WHERE id=?', (run_id,)).fetchone()
        if not row or row['state'] != 'active' or row['expires'] <= self._now():
            raise EnrollmentDenied('run is expired or revoked')
        self._trusted_row(row)
        self._connection(db, row['connection'])
        actual = json.loads(row['binding'])
        if binding is not None and actual != binding:
            raise EnrollmentDenied('run grant binding mismatch')
        self._current(actual, row['owner'], row['subject'], row['client'])
        return row

    def get_run(self, run_id: str) -> dict:
        """Pure authorization read: no replay/nonce/state mutations."""
        self._ready()
        with self._read() as db:
            return self._run_summary(self._run(db, run_id))

    def issue_nonce(self, run_id: str) -> str:
        """A command, not a read: non-secret challenge does not authorize a run."""
        self._ready()
        with self._tx() as db:
            run = self._run(db, run_id)
            return self._new_nonce(db, run_id, run['expires'])

    def _validate(self, db, run_id: str, proof: str, method: str, url: str,
                  nonce: str, grant_binding: dict, body_digest: str):
        binding = _binding(grant_binding)
        run = self._run(db, run_id, binding)
        if not _nonce(nonce):
            raise EnrollmentDenied('invalid request nonce')
        nonce_row = db.execute('SELECT * FROM coordinator_nonces WHERE hash=?', (_hash(nonce),)).fetchone()
        if (not nonce_row or nonce_row['run_id'] != run_id or nonce_row['used']
                or nonce_row['expires'] <= self._now()):
            raise EnrollmentDenied('request nonce is expired or consumed')
        claims = self._proof(proof, json.loads(run['public_jwk']), method, url, nonce,
                             binding, 'run_id', run_id, body_digest)
        self._record_proof(db, run['thumbprint'], claims)
        db.execute('UPDATE coordinator_nonces SET used=1 WHERE hash=?', (_hash(nonce),))
        return run

    def validate_request(self, run_id: str, proof: str, method: str, url: str,
                         nonce: str, grant_binding: dict, *, body_digest: str = EMPTY_BODY_DIGEST) -> dict:
        self._ready()
        with self._tx() as db:
            run = self._validate(db, run_id, proof, method, url, nonce, grant_binding, body_digest)
            return {**self._run_summary(run), 'nonce': self._new_nonce(db, run_id, run['expires'])}

    def renew(self, run_id: str, proof: str, method: str, url: str,
              nonce: str, grant_binding: dict, lifetime: int, *, body_digest: str = EMPTY_BODY_DIGEST) -> dict:
        self._ready()
        if type(lifetime) is not int or lifetime < 1:
            raise EnrollmentDenied('invalid renewal lifetime')
        with self._tx() as db:
            run = self._validate(db, run_id, proof, method, url, nonce, grant_binding, body_digest)
            expires = max(run['expires'], self._now() + lifetime)
            if expires > run['max_expires']:
                raise EnrollmentDenied('renewal exceeds original coordinator authority')
            db.execute('UPDATE coordinator_runs SET expires=? WHERE id=?', (expires, run_id))
            run = db.execute('SELECT * FROM coordinator_runs WHERE id=?', (run_id,)).fetchone()
            return {**self._run_summary(run), 'nonce': self._new_nonce(db, run_id, expires)}

    def revoke_run(self, run_id: str, principal: Principal):
        self._ready()
        trust = self._trust(principal)
        with self._tx() as db:
            row = db.execute('SELECT * FROM coordinator_runs WHERE id=?', (run_id,)).fetchone()
            if not row or self._trusted_row(row) != trust:
                raise EnrollmentDenied('run does not belong to coordinator connection')
            db.execute("UPDATE coordinator_runs SET state='revoked' WHERE id=?", (run_id,))

    def revoke_connection(self, connection_id: str, principal: Principal):
        self._ready()
        trust = self._trust(principal)
        if trust.connection_id != connection_id:
            raise EnrollmentDenied('coordinator connection mismatch')
        with self._tx() as db:
            db.execute('INSERT OR IGNORE INTO coordinator_revoked_connections VALUES (?,?)',
                       (connection_id, self._now()))
