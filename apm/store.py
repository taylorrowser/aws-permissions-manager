"""DynamoDB state: the request queue, agent API keys and push subscriptions. AWS IAM is the
source of truth for what is granted, so editing this table cannot grant anything."""
import contextlib
import hashlib
import json
import secrets
import time
from decimal import Decimal

PENDING_LIMIT = 20  # per API key, so a runaway agent can't flood the owner
CONNECT_LIMIT = 5  # unexpired connect requests at once; that endpoint needs no API key
CONNECT_SECONDS = 900
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
LEASE_SECONDS = 45  # longer than the Lambda timeout, so a crashed holder's lease always lapses


class Conflict(Exception):
    pass


def _plain(v):
    if isinstance(v, Decimal):
        return int(v)
    if isinstance(v, list):
        return [_plain(x) for x in v]
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    return v


def _hash(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


class Store:
    def __init__(self, table):
        self.t = table

    def _scan(self, kind, consistent=False):
        items, kw = [], {"FilterExpression": "kind = :k", "ExpressionAttributeValues": {":k": kind},
                         "ConsistentRead": consistent}
        while True:
            page = self.t.scan(**kw)
            items += page["Items"]
            if "LastEvaluatedKey" not in page:
                return [_plain(i) for i in items]
            kw["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    # ---------- leases: one writer per project policy across Lambda instances ----------

    @contextlib.contextmanager
    def lease(self, name, wait=10.0, poll=0.2):
        pk, token = f"lease#{name}", secrets.token_hex(8)
        deadline = time.time() + wait
        while True:
            now = time.time()
            try:
                self.t.put_item(Item={"pk": pk, "kind": "lease", "token": token, "expires_at": int(now) + LEASE_SECONDS},
                                ConditionExpression="attribute_not_exists(pk) OR expires_at < :now",
                                ExpressionAttributeValues={":now": int(now)})
                break
            except Exception as e:
                if getattr(e, "response", {}).get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                    raise
                if now > deadline:
                    raise Conflict(f"another change to {name} is in progress; try again in a moment")
                time.sleep(poll)
        try:
            yield
        finally:
            try:
                self.t.delete_item(Key={"pk": pk}, ConditionExpression="#t = :t",
                                   ExpressionAttributeNames={"#t": "token"}, ExpressionAttributeValues={":t": token})
            except Exception as e:
                if getattr(e, "response", {}).get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                    raise  # ours lapsed and someone else holds it now; leave theirs alone

    # ---------- requests ----------

    def add(self, project, actions, resources, reason, requester=""):
        rid = int(self.t.update_item(
            Key={"pk": "counter#request"}, UpdateExpression="ADD n :one",
            ExpressionAttributeValues={":one": 1}, ReturnValues="UPDATED_NEW")["Attributes"]["n"])
        self.t.put_item(Item={
            "pk": f"req#{rid}", "kind": "req", "id": rid, "project": project, "actions": actions,
            "resources": resources, "reason": reason, "requester": requester, "status": "pending",
            "note": "", "created_at": int(time.time()), "decided_at": 0})
        return rid

    def get(self, request_id, consistent=False):
        item = self.t.get_item(Key={"pk": f"req#{int(request_id)}"}, ConsistentRead=consistent).get("Item")
        return _view(_plain(item)) if item else None

    def list(self, status=None, project=None):
        rows = [_view(r) for r in self._scan("req")
                if (not status or r["status"] == status) and (not project or r["project"] == project)]
        return sorted(rows, key=lambda r: r["id"], reverse=True)

    def approved(self, project):
        """Approved requests for a project, read strongly consistent: what its role must grant."""
        return [_view(r) for r in self._scan("req", consistent=True)
                if r["project"] == project and r["status"] == "approved"]

    def projects(self):
        return sorted({r["project"] for r in self._scan("req") if r["status"] in ("approved", "revoked")})

    def pending_count(self, requester):
        return sum(1 for r in self._scan("req") if r["status"] == "pending" and r["requester"] == requester)

    def set_status(self, request_id, status, note="", expect=None):
        kw = {}
        if expect:
            kw = {"ConditionExpression": "#s = :expect", "ExpressionAttributeValues": {":expect": expect}}
        kw.setdefault("ExpressionAttributeValues", {}).update({":s": status, ":n": note, ":t": int(time.time())})
        try:
            self.t.update_item(Key={"pk": f"req#{int(request_id)}"}, UpdateExpression="SET #s = :s, note = :n, decided_at = :t",
                               ExpressionAttributeNames={"#s": "status"}, **kw)
        except Exception as e:
            if getattr(e, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise Conflict(f"request #{request_id} is no longer {expect}")
            raise

    # ---------- agent API keys (only a hash is stored) ----------

    def create_key(self, name):
        secret = "apm_" + secrets.token_urlsafe(32)
        self._put_key(name, _hash(secret), secret[:10])
        return secret

    def _put_key(self, name, key_hash, prefix):
        self.t.put_item(Item={"pk": f"key#{key_hash}", "kind": "key", "name": name,
                              "prefix": prefix, "created_at": int(time.time()), "last_used": 0})

    def find_key(self, secret):
        if not secret or not secret.startswith("apm_"):
            return None
        pk = f"key#{_hash(secret)}"
        item = self.t.get_item(Key={"pk": pk}).get("Item")
        if not item:
            return None
        now = int(time.time())
        if now - int(item.get("last_used", 0)) > 300:
            self.t.update_item(Key={"pk": pk}, UpdateExpression="SET last_used = :t", ExpressionAttributeValues={":t": now})
        return _plain(item)

    def keys(self):
        return sorted(self._scan("key"), key=lambda k: k["created_at"])

    def delete_key(self, pk):
        if pk.startswith("key#"):
            self.t.delete_item(Key={"pk": pk})

    # ---------- connect: an agent asks for a key from the browser ----------
    # The agent generates its key and sends only the hash; approving stores it like any other key.

    def add_connect(self, name, key_hash, prefix, origin_info=""):
        now = int(time.time())
        live = self.connects()
        if len(live) >= CONNECT_LIMIT:
            raise Conflict("too many pending connect requests; approve or reject them first")
        if self.t.get_item(Key={"pk": f"key#{key_hash}"}).get("Item") or any(c["key_hash"] == key_hash for c in live):
            raise Conflict("that key is already registered")
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
        code = f"{code[:4]}-{code[4:]}"
        self.t.put_item(Item={"pk": f"connect#{code}", "kind": "connect", "code": code, "name": name,
                              "key_hash": key_hash, "prefix": prefix, "info": origin_info[:200],
                              "status": "pending", "created_at": now, "expires_at": now + CONNECT_SECONDS})
        return code

    def connects(self):
        """Pending, unexpired connect requests. Expired ones are deleted on the way."""
        out, now = [], time.time()
        for c in self._scan("connect"):
            if c["expires_at"] < now:
                self.t.delete_item(Key={"pk": c["pk"]})
            elif c["status"] == "pending":
                out.append(c)
        return sorted(out, key=lambda c: c["created_at"])

    def decide_connect(self, code, approve):
        item = self.t.get_item(Key={"pk": f"connect#{code}"}).get("Item")
        c = _plain(item) if item else None
        if not c or c["status"] != "pending" or c["expires_at"] < time.time():
            raise Conflict("that connect request is no longer pending")
        try:
            self.t.update_item(Key={"pk": c["pk"]}, UpdateExpression="SET #s = :s", ConditionExpression="#s = :expect",
                               ExpressionAttributeNames={"#s": "status"},
                               ExpressionAttributeValues={":s": "approved" if approve else "rejected", ":expect": "pending"})
        except Exception as e:
            if getattr(e, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise Conflict("that connect request is no longer pending")
            raise
        if approve:
            self._put_key(c["name"], c["key_hash"], c["prefix"])
        return c

    def connect_status(self, secret):
        """approved / pending / rejected / expired, for the agent polling with its own key."""
        key_hash = _hash(secret)
        if self.t.get_item(Key={"pk": f"key#{key_hash}"}).get("Item"):
            return "approved"
        for c in self._scan("connect"):
            if c["key_hash"] == key_hash and c["expires_at"] >= time.time():
                return c["status"]
        return "expired"

    # ---------- web push subscriptions ----------

    def add_subscription(self, sub, label):
        """Save a device's push subscription (idempotent). Returns its id. Re-saving keeps when it
        was first added and its delivery history."""
        pk = subscription_id(sub["endpoint"])
        old = _plain(self.t.get_item(Key={"pk": pk}).get("Item") or {})
        self.t.put_item(Item={**old, "pk": pk, "kind": "sub", "sub": json.dumps(sub), "label": label[:120],
                              "created_at": old.get("created_at") or int(time.time())})
        return pk

    def subscriptions(self):
        return sorted(({**s, "sub": json.loads(s["sub"])} for s in self._scan("sub")), key=lambda s: s["created_at"])

    def delete_subscription(self, pk):
        if pk.startswith("sub#"):
            self.t.delete_item(Key={"pk": pk})

    def remove_device(self, pk):
        """The owner removed a device: delete it and remember that, so the device's browser,
        which still holds its subscription, can't quietly sign itself up again."""
        if pk.startswith("sub#"):
            self.delete_subscription(pk)
            self.t.put_item(Item={"pk": "subgone#" + pk[4:], "kind": "subgone", "created_at": int(time.time())})

    def device_removed(self, pk):
        return bool(self.t.get_item(Key={"pk": "subgone#" + pk[4:]}).get("Item"))

    def clear_removed(self, pk):
        self.t.delete_item(Key={"pk": "subgone#" + pk[4:]})

    def record_delivery(self, pk, ok, status):
        """Remember the last push outcome per device so the dashboard can show broken devices."""
        now = int(time.time())
        expr = "SET last_ok_at = :t, last_status = :s, failures = :z" if ok else \
            "SET last_error_at = :t, last_status = :s ADD failures :one"
        values = {":t": now, ":s": status or 0, **({":z": 0} if ok else {":one": 1})}
        try:
            self.t.update_item(Key={"pk": pk}, UpdateExpression=expr, ExpressionAttributeValues=values,
                               ConditionExpression="attribute_exists(pk)")
        except Exception as e:
            if getattr(e, "response", {}).get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise  # a missing device was removed meanwhile; nothing to record


def subscription_id(endpoint):
    return f"sub#{_hash(endpoint)}"


def _view(r):
    r = dict(r)
    r["digest"] = digest(r)
    return r


def digest(r):
    """Fingerprint of what the owner sees, so a request edited after the page loaded can't be approved."""
    body = json.dumps([r["id"], r["project"], r["actions"], r["resources"], r["reason"]])
    return hashlib.sha256(body.encode()).hexdigest()
