"""Synthetic permission broker. No cloud SDK, real credential, or network adapter."""
import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager

SIMULATION = 'SIMULATED — no permissions or cloud resources are changed'
COMPILER = 'synthetic-compiler-v1'
CAPABILITY = 'plants.inventory.read.synthetic.v1'
# Public demo fixtures, deliberately not credentials or production authentication.
IDENTITIES = {'demo-agent': ('agent-preview', 'requester'),
              'demo-other-agent': ('agent-other', 'requester'),
              'demo-owner': ('owner-alice', 'owner')}
CATALOG = {
    'preview-read': {'role_id': 'SIM-ROLE-PREVIEW-1', 'environment': 'preview',
                     'resources': ['sim://preview/projects', 'sim://preview/devices']},
    'live-inventory-read': {'role_id': 'SIM-ROLE-LIVE-1', 'environment': 'live',
                            'resources': ['sim://live/projects', 'sim://live/devices']},
}

class Denied(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def identity(token, kind=None):
    found = IDENTITIES.get(token)
    if found is None or (kind is not None and found[1] != kind):
        raise Denied('unauthorized demo identity')
    return found[0]


def policy(role, cutoff):
    if role not in CATALOG:
        raise Denied('role outside fixed synthetic catalog')
    return {'simulation': True, 'actions': ['inventory:read'],
            'resources': CATALOG[role]['resources'], 'project': 'plants',
            'not_after': cutoff, 'boundary_version': 'synthetic-read-boundary-v1'}


class Store:
    def __init__(self, path, clock=time.time):
        self.path, self.clock = str(path), clock
        with self.tx() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS requests (
                  id TEXT PRIMARY KEY, manifest TEXT NOT NULL, digest TEXT NOT NULL,
                  state TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS decisions (
                  request_id TEXT PRIMARY KEY, digest TEXT NOT NULL,
                  owner TEXT NOT NULL, choice TEXT NOT NULL, decided_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS roles (
                  name TEXT PRIMARY KEY, role_id TEXT NOT NULL, policy TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS receipts (
                  operation_id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL,
                  result TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS fake_mutations (
                  seq INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT NOT NULL, policy_digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS execution_attempts (
                  request_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
                  recovery TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS reservation_releases (
                  request_id TEXT PRIMARY KEY, released_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS reservations (
                  role TEXT NOT NULL, request_id TEXT NOT NULL,
                  PRIMARY KEY(role, request_id));
                CREATE TABLE IF NOT EXISTS sessions (
                  id TEXT PRIMARY KEY, request_id TEXT NOT NULL, role TEXT NOT NULL,
                  audience TEXT NOT NULL, expires INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS journal (
                  seq INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER NOT NULL,
                  request_id TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS frozen_request
                  BEFORE UPDATE OF manifest, digest ON requests
                  BEGIN SELECT RAISE(ABORT, 'immutable request: submit a new request'); END;
                CREATE TRIGGER IF NOT EXISTS frozen_request_delete BEFORE DELETE ON requests
                  BEGIN SELECT RAISE(ABORT, 'immutable request'); END;
                CREATE TRIGGER IF NOT EXISTS frozen_decision_update BEFORE UPDATE ON decisions
                  BEGIN SELECT RAISE(ABORT, 'immutable decision'); END;
                CREATE TRIGGER IF NOT EXISTS frozen_decision_delete BEFORE DELETE ON decisions
                  BEGIN SELECT RAISE(ABORT, 'immutable decision'); END;
                CREATE TRIGGER IF NOT EXISTS journal_update BEFORE UPDATE ON journal
                  BEGIN SELECT RAISE(ABORT, 'append-only journal'); END;
                CREATE TRIGGER IF NOT EXISTS journal_delete BEFORE DELETE ON journal
                  BEGIN SELECT RAISE(ABORT, 'append-only journal'); END;
            ''')
            for name, spec in CATALOG.items():
                db.execute('INSERT OR IGNORE INTO roles VALUES (?,?,?)',
                           (name, spec['role_id'], canonical({})))
            self.sync_reservations(db)

    @contextmanager
    def tx(self):
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

    def event(self, db, rid, event, detail=''):
        db.execute('INSERT INTO journal(time,request_id,event,detail) VALUES (?,?,?,?)',
                   (int(self.clock()), rid, event, detail))

    def row(self, db, rid):
        row = db.execute('SELECT * FROM requests WHERE id=?', (rid,)).fetchone()
        if row is None:
            raise Denied('unknown request')
        return row

    def checked_manifest(self, row):
        m = json.loads(row['manifest'])
        if digest(m) != row['digest'] or m['compiler'] != COMPILER:
            raise Denied('manifest integrity or compiler mismatch')
        if m['revision'] != 1 or m['request_id'] != row['id'] or m['audience'] not in ('agent-preview', 'agent-other'):
            raise Denied('invalid frozen revision, request identity or audience')
        if m['capability'] != CAPABILITY:
            raise Denied('unknown capability version')
        if m['simulation'] is not True or not m['roles'] or len(set(m['roles'])) != len(m['roles']):
            raise Denied('invalid manifest')
        if m['application_grant'] != {'project': 'plants', 'actions': ['devices:read']}:
            raise Denied('unapproved application grant')
        if m['session_seconds'] != 900 or not (0 < m['expires_at'] - m['created_at'] <= 86400):
            raise Denied('invalid grant bounds')
        if set(m['targets']) != set(m['roles']):
            raise Denied('target mismatch')
        for role in m['roles']:
            if role not in CATALOG or m['targets'][role]['role_id'] != CATALOG[role]['role_id']:
                raise Denied('unapproved role identity')
            if m['targets'][role]['desired_policy'] != policy(role, m['expires_at']):
                raise Denied('unapproved policy expansion')
        return m

    def submit(self, token, data):
        audience = identity(token, 'requester')
        if set(data) != {'roles', 'reason', 'ttl_seconds', 'task_environment'}:
            raise Denied('only roles, reason, ttl_seconds and task_environment are accepted')
        roles, reason, ttl = data['roles'], data['reason'], data['ttl_seconds']
        if (not isinstance(roles, list) or not roles or len(roles) > len(CATALOG)
                or any(not isinstance(r, str) or r not in CATALOG for r in roles)
                or len(set(roles)) != len(roles)):
            raise Denied('roles must be distinct fixed catalog roles')
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
            raise Denied('human-readable reason required (1–2000 characters)')
        if type(ttl) is not int or not 1 <= ttl <= 86400:
            raise Denied('grant duration must be 1–86400 seconds')
        if data['task_environment'] not in ('preview', 'live'):
            raise Denied('unsupported task label')
        now, rid = int(self.clock()), 'sim-request-' + uuid.uuid4().hex
        with self.tx() as db:
            targets = {}
            for role in sorted(roles):
                baseline = db.execute('SELECT * FROM roles WHERE name=?', (role,)).fetchone()
                if baseline['role_id'] != CATALOG[role]['role_id']:
                    raise Denied('catalog role identity drift')
                targets[role] = {'role_id': baseline['role_id'],
                                 'baseline_digest': digest(json.loads(baseline['policy'])),
                                 'desired_policy': policy(role, now + ttl)}
            m = {'simulation': True, 'revision': 1, 'request_id': rid, 'capability': CAPABILITY,
                 'audience': audience, 'task_environment': data['task_environment'],
                 'reason': reason, 'roles': sorted(roles), 'targets': targets,
                 'created_at': now, 'expires_at': now + ttl, 'session_seconds': 900,
                 'compiler': COMPILER, 'application_grant': {'project': 'plants', 'actions': ['devices:read']},
                 'estimated_cost': 'SIMULATED: no cloud cost',
                 'cleanup_owner': 'owner-alice', 'rollback': 'stop simulated issuance; deny at cutoff'}
            db.execute('INSERT INTO requests VALUES (?,?,?,?)', (rid, canonical(m), digest(m), 'awaiting_owner'))
            self.event(db, rid, 'submitted', digest(m))
        return self.status(token, rid)

    def decide(self, token, rid, choice, expected_digest):
        owner = identity(token, 'owner')
        if choice not in ('approve', 'reject'):
            raise Denied('unknown decision')
        with self.tx() as db:
            row = self.row(db, rid)
            m = self.checked_manifest(row)
            if row['digest'] != expected_digest:
                raise Denied('owner must decide the exact displayed digest')
            if row['state'] != 'awaiting_owner' or int(self.clock()) >= m['expires_at']:
                raise Denied('request is no longer awaiting a decision or has expired')
            db.execute('INSERT INTO decisions VALUES (?,?,?,?,?)',
                       (rid, row['digest'], owner, choice, int(self.clock())))
            db.execute('UPDATE requests SET state=? WHERE id=?',
                       ('approved' if choice == 'approve' else 'rejected', rid))
            self.event(db, rid, choice, row['digest'])
        return self.status(token, rid)

    def attempt_evidence(self, db, rid):
        # Invocation or a blocked request is NOT evidence that a write was attempted.
        return (db.execute('SELECT 1 FROM receipts WHERE request_id=?', (rid,)).fetchone()
                or db.execute("SELECT 1 FROM journal WHERE request_id=? AND event IN "
                              "('applying','timeout_after_fake_put','active') LIMIT 1", (rid,)).fetchone())

    def sync_reservations(self, db):
        """Conservative migration; provider policies are never changed here.

        New attempts acquire all claims atomically under BEGIN IMMEDIATE. Composite
        keys preserve conflicting legacy claims rather than silently losing one;
        any claim by another request blocks new execution until safely released.
        """
        rows = db.execute('SELECT * FROM requests').fetchall()
        for row in rows:
            rid = row['id']
            if not self.attempt_evidence(db, rid):
                db.execute('DELETE FROM reservations WHERE request_id=?', (rid,))
                db.execute('DELETE FROM execution_attempts WHERE request_id=?', (rid,))
                db.execute('DELETE FROM reservation_releases WHERE request_id=?', (rid,))
                continue
            m = self.checked_manifest(row)
            attempt = db.execute('SELECT * FROM execution_attempts WHERE request_id=?', (rid,)).fetchone()
            if not attempt:
                last = db.execute("SELECT event FROM journal WHERE request_id=? AND event IN "
                                  "('applying','timeout_after_fake_put','active','needs_review') "
                                  "ORDER BY seq DESC LIMIT 1", (rid,)).fetchone()
                receipt = db.execute('SELECT 1 FROM receipts WHERE request_id=?', (rid,)).fetchone()
                known = receipt and (not last or last['event'] == 'active') and row['state'] != 'needs_review'
                recovery = 'complete' if known else 'unknown'
                db.execute('INSERT INTO execution_attempts VALUES (?,?,?)',
                           (rid, self.operation_id(row), recovery))
            else:
                recovery = attempt['recovery']
            if db.execute('SELECT 1 FROM reservation_releases WHERE request_id=?', (rid,)).fetchone():
                # A successor owns future state. Never resurrect an old released claim.
                db.execute('DELETE FROM reservations WHERE request_id=?', (rid,))
                continue
            uncertain = recovery in ('uncertain', 'unknown', 'applying')
            if not uncertain and int(self.clock()) >= m['expires_at']:
                observed = self.observations(db, m)
                known = ('unknown' not in observed and
                         (recovery != 'complete' or all(x == 'desired' for x in observed)))
                if not known:
                    recovery, uncertain = 'unknown', True
                    db.execute("UPDATE execution_attempts SET recovery='unknown' WHERE request_id=?", (rid,))
                    if row['state'] not in ('cancelled', 'revoked', 'rejected'):
                        db.execute("UPDATE requests SET state='needs_review' WHERE id=?", (rid,))
                    self.event(db, rid, 'needs_review', 'drift observed before cutoff reservation release')
            if uncertain or int(self.clock()) < m['expires_at']:
                for role in m['roles']:
                    db.execute('INSERT OR IGNORE INTO reservations VALUES (?,?)', (role, rid))
            else:
                db.execute('DELETE FROM reservations WHERE request_id=?', (rid,))
                db.execute('INSERT OR IGNORE INTO reservation_releases VALUES (?,?)', (rid, int(self.clock())))

    @staticmethod
    def operation_id(row):
        return 'sim-op-' + digest({'id': row['id'], 'digest': row['digest']})

    def mark_drift(self, db, row, m):
        if row['state'] not in ('active', 'issuance_stopped') or int(self.clock()) >= m['expires_at']:
            return row
        for role, target in m['targets'].items():
            live = db.execute('SELECT * FROM roles WHERE name=?', (role,)).fetchone()
            if not live or live['role_id'] != target['role_id'] or json.loads(live['policy']) != target['desired_policy']:
                db.execute("UPDATE requests SET state='needs_review' WHERE id=?", (row['id'],))
                db.execute("UPDATE execution_attempts SET recovery='unknown' WHERE request_id=?", (row['id'],))
                self.event(db, row['id'], 'needs_review', 'role identity or policy drift; quarantine retained')
                self.sync_reservations(db)
                return self.row(db, row['id'])
        return row

    def status(self, token, rid):
        who = identity(token)
        with self.tx() as db:
            row = self.row(db, rid)
            m = self.checked_manifest(row)
            if who != m['audience'] and IDENTITIES[token][1] != 'owner':
                raise Denied('request belongs to another audience')
            self.sync_reservations(db)
            row = self.mark_drift(db, self.row(db, rid), m)
            attempt = db.execute('SELECT * FROM execution_attempts WHERE request_id=?', (rid,)).fetchone()
            recovery = attempt['recovery'] if attempt else 'not_attempted'
            recovery_required = recovery in ('uncertain', 'unknown', 'applying')
            state = row['state']
            expired = int(self.clock()) >= m['expires_at']
            if state not in ('rejected', 'revoked', 'cancelled', 'needs_review') and expired:
                state = 'expired'
            controls = []
            if IDENTITIES[token][1] == 'owner':
                if row['state'] not in ('rejected', 'revoked', 'cancelled'):
                    controls.append('cancel')
                if recovery_required:
                    controls.append('reconcile')
                if row['state'] in ('active', 'issuance_stopped') and not expired:
                    controls.extend(['stop_issuance', 'revoke'])
            return {'simulation': SIMULATION, 'id': rid, 'digest': row['digest'],
                    'state': state, 'stored_state': row['state'], 'expired': expired,
                    'recovery': recovery, 'recovery_required': recovery_required,
                    'available_controls': controls, 'manifest': m,
                    'journal': [dict(x) for x in db.execute(
                        'SELECT time,event,detail FROM journal WHERE request_id=? ORDER BY seq', (rid,))]}

    def control(self, token, rid, action, expected_digest):
        identity(token, 'owner')
        if action not in ('stop_issuance', 'revoke', 'cancel'):
            raise Denied('unsupported control action')
        with self.tx() as db:
            row = self.row(db, rid)
            self.checked_manifest(row)
            if row['digest'] != expected_digest:
                raise Denied('control requires exact displayed digest')
            if action == 'cancel':
                if row['state'] in ('rejected', 'revoked'):
                    raise Denied('terminal request')
                state = 'cancelled'
                detail = 'No later execution or issuance; uncertain writes require read-only reconciliation'
            else:
                if row['state'] not in ('active', 'issuance_stopped'):
                    raise Denied('control requires exact active grant')
                state = 'issuance_stopped' if action == 'stop_issuance' else 'revoked'
                detail = ('SIMULATED effective deny; cleanup separate' if action == 'revoke'
                          else 'New issuance denied; existing simulated sessions still valid until cutoff')
            db.execute('UPDATE requests SET state=? WHERE id=?', (state, rid))
            self.event(db, rid, state, detail)
            self.sync_reservations(db)
        return self.status(token, rid)

    def reconcile(self, token, rid, expected_digest):
        identity(token, 'owner')
        with self.tx() as db:
            row = self.row(db, rid)
            if row['digest'] != expected_digest:
                raise Denied('reconciliation requires exact displayed digest')
            self._reconcile(db, row)
        return self.status(token, rid)

    def observations(self, db, m):
        observations = []
        for role, target in m['targets'].items():
            live = db.execute('SELECT * FROM roles WHERE name=?', (role,)).fetchone()
            if not live or live['role_id'] != target['role_id']:
                observations.append('unknown')
                continue
            current = json.loads(live['policy'])
            observations.append('desired' if current == target['desired_policy'] else
                                'baseline' if digest(current) == target['baseline_digest'] else 'unknown')
        return observations

    def _reconcile(self, db, row):
        """Read provider state only. Never calls FakeIAM, even after expiry/cancel."""
        m = self.checked_manifest(row)
        self.sync_reservations(db)
        if not self.attempt_evidence(db, row['id']):
            raise Denied('no durable execution-attempt evidence to reconcile')
        if db.execute('SELECT 1 FROM reservation_releases WHERE request_id=?', (row['id'],)).fetchone():
            return {'simulation': SIMULATION, 'state': row['state'], 'provider_writes': 0,
                    'already_released': True, 'operation_id': self.operation_id(row)}
        observations = self.observations(db, m)
        recovery = ('unknown' if 'unknown' in observations else
                    'complete' if all(x == 'desired' for x in observations) else 'partial')
        if recovery == 'partial' and db.execute('SELECT 1 FROM receipts WHERE request_id=?', (row['id'],)).fetchone():
            # A completed grant regressing to baseline is drift, not unfinished work.
            recovery = 'unknown'
        db.execute('UPDATE execution_attempts SET recovery=? WHERE request_id=?', (recovery, row['id']))
        terminal = row['state'] in ('cancelled', 'revoked', 'rejected', 'issuance_stopped')
        expired = int(self.clock()) >= m['expires_at']
        state = row['state']
        if not terminal:
            state = 'needs_review' if recovery == 'unknown' else ('expired' if expired else
                    'active' if recovery == 'complete' else 'ready_to_resume')
            if state == 'active':
                Executor(self).check_decision(db, row)
                Executor(self).record_receipt(db, row, m)
                if db.execute("SELECT 1 FROM journal WHERE request_id=? AND event='issuance_stopped' LIMIT 1", (row['id'],)).fetchone():
                    state = 'issuance_stopped'

            db.execute('UPDATE requests SET state=? WHERE id=?', (state, row['id']))
        self.event(db, row['id'], 'read_only_reconciliation', recovery)
        self.sync_reservations(db)
        return {'simulation': SIMULATION, 'state': state, 'recovery': recovery,
                'provider_writes': 0, 'operation_id': self.operation_id(row)}

    def list_requests(self, token):
        who = identity(token)
        with self.tx() as db:
            ids = [r['id'] for r in db.execute('SELECT * FROM requests ORDER BY rowid DESC')
                   if IDENTITIES[token][1] == 'owner' or json.loads(r['manifest'])['audience'] == who]
        return [self.status(token, rid) for rid in ids]


class FakeIAM:
    """Only a SQLite simulation; never creates roles, changes trust, or calls AWS."""
    def apply(self, db, role, expected_id, desired):
        if role not in CATALOG or expected_id != CATALOG[role]['role_id']:
            raise Denied('executor target outside boundary')
        if desired != policy(role, desired['not_after']):
            raise Denied('executor policy outside boundary')
        db.execute('INSERT INTO fake_mutations(role,policy_digest) VALUES (?,?)', (role, digest(desired)))
        db.execute('UPDATE roles SET policy=? WHERE name=? AND role_id=?',
                   (canonical(desired), role, expected_id))


class Executor:
    """Invoked by executor.py, never by the dashboard or request HTTP handlers."""
    def __init__(self, store):
        self.store, self.iam = store, FakeIAM()

    @staticmethod
    def check_decision(db, row):
        decision = db.execute('SELECT * FROM decisions WHERE request_id=?', (row['id'],)).fetchone()
        if not decision or decision['choice'] != 'approve' or decision['owner'] != 'owner-alice' or decision['digest'] != row['digest']:
            raise Denied('exact protected owner approval required')

    def record_receipt(self, db, row, m):
        operation_id = self.store.operation_id(row)
        result = {'simulation': SIMULATION, 'state': 'active', 'operation_id': operation_id,
                  'roles': m['roles'], 'duplicate': False}
        db.execute('INSERT OR IGNORE INTO receipts VALUES (?,?,?)', (operation_id, row['id'], canonical(result)))
        return result

    def execute(self, rid, timeout_after_write=False):
        s = self.store
        with s.tx() as db:
            row = s.row(db, rid)
            m = s.checked_manifest(row)
            self.check_decision(db, row)
            if int(s.clock()) >= m['expires_at']:
                raise Denied('grant expired; use owner read-only reconciliation if uncertain')
            if row['state'] not in ('approved', 'active', 'reconciling', 'ready_to_resume', 'blocked_overlap'):
                raise Denied('state does not permit execution')
            s.sync_reservations(db)
            if row['state'] == 'reconciling':
                return s._reconcile(db, row)
            operation_id = s.operation_id(row)
            receipt = db.execute('SELECT * FROM receipts WHERE operation_id=?', (operation_id,)).fetchone()
            for role in m['roles']:
                if db.execute('SELECT 1 FROM reservations WHERE role=? AND request_id<>? LIMIT 1', (role, rid)).fetchone():
                    db.execute("UPDATE requests SET state='blocked_overlap' WHERE id=?", (rid,))
                    s.event(db, rid, 'blocked_overlap', 'another grant retains role reservation; no roles touched')
                    return {'simulation': SIMULATION, 'state': 'blocked_overlap', 'provider_writes': 0}
            pending = []
            for role, target in m['targets'].items():
                live = db.execute('SELECT * FROM roles WHERE name=?', (role,)).fetchone()
                current = json.loads(live['policy']) if live else None
                is_desired = current == target['desired_policy']
                is_baseline = digest(current) == target['baseline_digest']
                resume = row['state'] == 'ready_to_resume'
                expected = is_desired if receipt else (is_baseline or (resume and is_desired))
                if not live or live['role_id'] != target['role_id'] or not expected:
                    db.execute("UPDATE requests SET state='needs_review' WHERE id=?", (rid,))
                    db.execute("UPDATE execution_attempts SET recovery='unknown' WHERE request_id=?", (rid,))
                    s.event(db, rid, 'needs_review', 'role identity or policy baseline changed')
                    s.sync_reservations(db)
                    return {'simulation': SIMULATION, 'state': 'needs_review'}
                if not receipt and not (resume and is_desired):
                    pending.append((role, target))
            if receipt:
                s.event(db, rid, 'duplicate_ignored', operation_id)
                return {**json.loads(receipt['result']), 'duplicate': True}
            # All targets validated and all conflicts checked before any reservation or write intent.
            s.event(db, rid, 'applying', operation_id)
            db.execute("INSERT INTO execution_attempts VALUES (?,?,'applying') ON CONFLICT(request_id) DO UPDATE SET recovery='applying'", (rid, operation_id))
            for role in m['roles']:
                db.execute('INSERT OR IGNORE INTO reservations VALUES (?,?)', (role, rid))
            for role, target in pending:
                self.iam.apply(db, role, target['role_id'], target['desired_policy'])
                if timeout_after_write:
                    db.execute("UPDATE requests SET state='reconciling' WHERE id=?", (rid,))
                    db.execute("UPDATE execution_attempts SET recovery='uncertain' WHERE request_id=?", (rid,))
                    s.event(db, rid, 'timeout_after_fake_put', operation_id)
                    return {'simulation': SIMULATION, 'state': 'reconciling', 'operation_id': operation_id}
            result = self.record_receipt(db, row, m)
            db.execute("UPDATE requests SET state='active' WHERE id=?", (rid,))
            db.execute("UPDATE execution_attempts SET recovery='complete' WHERE request_id=?", (rid,))
            s.event(db, rid, 'active', operation_id)
            return result



class FakeSTS:
    """Returns a synthetic session identifier, never any credential-shaped secret."""
    def __init__(self, store):
        self.store = store

    def _active(self, db, rid, audience, role, existing_session=False):
        s = self.store
        row = s.row(db, rid)
        m = s.checked_manifest(row)
        d = db.execute('SELECT * FROM decisions WHERE request_id=?', (rid,)).fetchone()
        if (not d or d['choice'] != 'approve' or d['owner'] != 'owner-alice'
                or d['digest'] != row['digest'] or row['state'] not in
                (('active', 'issuance_stopped') if existing_session else ('active',))
                or audience != m['audience'] or role not in m['roles']
                or int(s.clock()) >= m['expires_at']):
            raise Denied('inactive, expired, wrong audience, or out-of-bundle role')
        live = db.execute('SELECT * FROM roles WHERE name=?', (role,)).fetchone()
        t = m['targets'][role]
        if not live or live['role_id'] != t['role_id'] or json.loads(live['policy']) != t['desired_policy']:
            raise Denied('role identity or policy drift')
        return m

    def vend(self, token, rid, role):
        audience = identity(token, 'requester')
        self.store.status(token, rid)  # Persist visible drift quarantine before issuing.
        with self.store.tx() as db:
            m = self._active(db, rid, audience, role)
            sid = 'SIMULATED-SESSION-' + uuid.uuid4().hex
            expires = min(int(self.store.clock()) + 900, m['expires_at'])
            db.execute('INSERT INTO sessions VALUES (?,?,?,?,?)', (sid, rid, role, audience, expires))
            self.store.event(db, rid, 'simulated_session_issued', role)
            return {'simulation': SIMULATION, 'session_id': sid, 'role': role,
                    'expires_at': expires, 'credentials': 'NONE — synthetic session only'}

    def read(self, token, sid, resource, project='plants'):
        audience = identity(token, 'requester')
        with self.store.tx() as db:
            session = db.execute('SELECT * FROM sessions WHERE id=?', (sid,)).fetchone()
            if not session or session['audience'] != audience or int(self.store.clock()) >= session['expires']:
                raise Denied('invalid or expired simulated session')
            m = self._active(db, session['request_id'], audience, session['role'], existing_session=True)
            if project != m['application_grant']['project'] or resource not in CATALOG[session['role']]['resources']:
                raise Denied('resource or application project outside approved scope')
            return {'simulation': SIMULATION, 'items': [{'id': 'synthetic-controller-001',
                     'project': 'plants', 'firmware': 'fixture-1.0', 'connected': True}]}
