"""Atomic browser-state stores. Durability is not a production isolation claim.

SQLite is an encrypted offline/reference implementation. Each operation maps to
one conditional/transactional storage command, rather than a distributed mutex.
Provider tokens are not stored here. No cloud client, key discovery or network.
"""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import asdict
import base64,hashlib,hmac,json,os,secrets,sqlite3,stat,threading
from typing import Protocol
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .auth import AuthError,AuthConfigurationError,AuthUnconfigured,Principal,BrowserSession,_PendingLogin,_Challenge

class RecordCipher(Protocol):
    def seal(self,plaintext:bytes,aad:bytes)->bytes: ...
    def open(self,ciphertext:bytes,aad:bytes)->bytes: ...

class AESGCMRecordCipher:
    """Explicit injected key, never obtained from environment or serialized.
    Live key provisioning/rotation/KMS remain separate approval-bound adapters.
    """
    def __init__(self,key:bytes):
        if not isinstance(key,bytes) or len(key)!=32: raise AuthConfigurationError('explicit 256-bit record key required')
        self._cipher=AESGCM(key)
    def __repr__(self):return 'AESGCMRecordCipher(key=<redacted>)'
    def seal(self,plaintext,aad):
        nonce=secrets.token_bytes(12);return nonce+self._cipher.encrypt(nonce,plaintext,aad)
    def open(self,ciphertext,aad):
        try:return self._cipher.decrypt(ciphertext[:12],ciphertext[12:],aad)
        except Exception:raise AuthError('browser state integrity failure') from None

class BrowserStateStore(Protocol):
    durable:bool
    production_ready:bool
    def create_login(self,key,value,context,now):...
    def consume_login(self,key,context,now):...
    def create_session(self,key,value,context,now):...
    def get_session(self,key,context,now):...
    def create_challenge(self,key,value,session,context,now):...
    def consume_challenge(self,key,session,request_id,revision,digest,context,now):...
    def revoke_session(self,key,context):...


def _session_matches(actual,expected,now):
    if not isinstance(actual,BrowserSession) or actual!=expected or actual.expires_at<=now:
        raise AuthError('owner browser authentication required')

def _challenge_matches(value,session,request_id,revision,digest,now):
    if (not isinstance(value,_Challenge) or value.expires_at<=now or value.session_key!=session._key
        or value.request_id!=request_id or value.revision!=revision or not hmac.compare_digest(value.digest,digest)):
        raise AuthError('invalid browser approval proof')

class MemoryBrowserState:
    durable=False;production_ready=False
    def __init__(self):
        self.pending={};self.sessions={};self.challenges={};self.contexts={};self.lock=threading.RLock()
    def _get(self,kind,key,context,now):
        store={'login':self.pending,'session':self.sessions,'challenge':self.challenges}[kind]
        value=store.get(key)
        if self.contexts.get((kind,key))!=context or value is None or value.expires_at<=now:return None
        return value
    def _put(self,kind,key,value,context):
        store={'login':self.pending,'session':self.sessions,'challenge':self.challenges}[kind]
        if key in store:raise AuthError('browser state collision')
        store[key]=value;self.contexts[kind,key]=context
    def create_login(self,key,value,context,now):
        with self.lock:self._put('login',key,value,context)
    def consume_login(self,key,context,now):
        with self.lock:
            value=self._get('login',key,context,now);self.pending.pop(key,None);self.contexts.pop(('login',key),None);return value
    def create_session(self,key,value,context,now):
        with self.lock:self._put('session',key,value,context)
    def get_session(self,key,context,now):
        with self.lock:return self._get('session',key,context,now)
    def create_challenge(self,key,value,session,context,now):
        with self.lock:
            _session_matches(self._get('session',session._key,context,now),session,now);self._put('challenge',key,value,context)
    def consume_challenge(self,key,session,request_id,revision,digest,context,now):
        with self.lock:
            _session_matches(self._get('session',session._key,context,now),session,now)
            value=self._get('challenge',key,context,now)
            self.challenges.pop(key,None);self.contexts.pop(('challenge',key),None)
            _challenge_matches(value,session,request_id,revision,digest,now)
            return session.principal
    def revoke_session(self,key,context):
        with self.lock:
            if self.contexts.get(('session',key))==context:
                self.sessions.pop(key,None);self.contexts.pop(('session',key),None)
            for challenge,value in list(self.challenges.items()):
                if value.session_key==key:
                    self.challenges.pop(challenge,None);self.contexts.pop(('challenge',challenge),None)

class SQLiteBrowserState:
    """Encrypted durable reference store with atomic compare/delete and pure reads.
    SQLite/process identity is not a hosted security boundary; production_ready
    deliberately remains False. Use an explicitly private database path.
    """
    durable=True;production_ready=False
    def __init__(self,path,*,cipher:RecordCipher|None=None):
        if cipher is None:raise AuthUnconfigured('explicit browser-state encryption adapter is required')
        self.path=str(path);self.cipher=cipher
        try:
            fd=os.open(self.path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
            try:
                info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise ValueError()
            finally:os.close(fd)
        except (OSError,ValueError):raise AuthConfigurationError('browser state requires an owner-only regular database') from None
        with self.tx() as db:
            db.execute('CREATE TABLE IF NOT EXISTS browser_state(kind TEXT,key TEXT,context TEXT,expires INTEGER,value BLOB,PRIMARY KEY(kind,key))')
    @contextmanager
    def tx(self):
        db=sqlite3.connect(self.path,timeout=10);db.row_factory=sqlite3.Row
        try:db.execute('BEGIN IMMEDIATE');yield db;db.commit()
        except BaseException:db.rollback();raise
        finally:db.close()
    @contextmanager
    def read(self):
        db=sqlite3.connect('file:'+self.path+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
        try:db.execute('PRAGMA query_only=ON');yield db
        finally:db.close()
    def _aad(self,kind,key,context,expires):
        return json.dumps(['broker-browser-state-v1',kind,key,context,expires],separators=(',',':')).encode()
    def _put(self,db,kind,key,value,context):
        encoded=json.dumps(asdict(value),sort_keys=True,separators=(',',':')).encode()
        sealed=self.cipher.seal(encoded,self._aad(kind,key,context,value.expires_at))
        try:db.execute('INSERT INTO browser_state VALUES (?,?,?,?,?)',(kind,key,context,value.expires_at,sealed))
        except sqlite3.IntegrityError:raise AuthError('browser state collision') from None
    def _get(self,db,kind,key,context,now):
        row=db.execute('SELECT * FROM browser_state WHERE kind=? AND key=?',(kind,key)).fetchone()
        if row is None or row['context']!=context or row['expires']<=now:return None
        try:
            data=json.loads(self.cipher.open(row['value'],self._aad(kind,key,context,row['expires'])))
            if data.get('approval_binding') is not None:data['approval_binding']=tuple(data['approval_binding'])
            if kind=='session':data['principal']=Principal(**data['principal']);value=BrowserSession(**data)
            elif kind=='login':value=_PendingLogin(**data)
            else:value=_Challenge(**data)
            if value.expires_at!=row['expires']:raise ValueError()
            return value
        except Exception:raise AuthError('browser state integrity failure') from None
    def create_login(self,key,value,context,now):
        with self.tx() as db:self._put(db,'login',key,value,context)
    def consume_login(self,key,context,now):
        with self.tx() as db:
            value=self._get(db,'login',key,context,now)
            db.execute("DELETE FROM browser_state WHERE kind='login' AND key=? AND context=?",(key,context));return value
    def create_session(self,key,value,context,now):
        with self.tx() as db:self._put(db,'session',key,value,context)
    def get_session(self,key,context,now):
        with self.read() as db:return self._get(db,'session',key,context,now)
    def create_challenge(self,key,value,session,context,now):
        with self.tx() as db:
            _session_matches(self._get(db,'session',session._key,context,now),session,now)
            self._put(db,'challenge',key,value,context)
    def consume_challenge(self,key,session,request_id,revision,digest,context,now):
        # The session condition and challenge consumption are one transaction.
        # Revocation that wins the transaction race prevents every later consume.
        failure=False
        with self.tx() as db:
            _session_matches(self._get(db,'session',session._key,context,now),session,now)
            value=self._get(db,'challenge',key,context,now)
            db.execute("DELETE FROM browser_state WHERE kind='challenge' AND key=? AND context=?",(key,context))
            try:_challenge_matches(value,session,request_id,revision,digest,now)
            except AuthError:failure=True
        if failure:raise AuthError('invalid browser approval proof')
        return session.principal
    def revoke_session(self,key,context):
        # Challenges cannot authorize without the session, even if TTL cleanup
        # has not deleted their encrypted orphan rows yet.
        with self.tx() as db:db.execute("DELETE FROM browser_state WHERE kind='session' AND key=? AND context=?",(key,context))
    def cleanup_expired(self,now,limit=100):
        """Explicit bounded maintenance command; authentication reads are pure."""
        if type(limit) is not int or not 1<=limit<=1000:raise AuthError('invalid browser cleanup bound')
        with self.tx() as db:
            rows=db.execute('SELECT kind,key FROM browser_state WHERE expires<=? ORDER BY expires LIMIT ?',(now,limit)).fetchall()
            db.executemany('DELETE FROM browser_state WHERE kind=? AND key=?',[(r['kind'],r['key']) for r in rows]);return len(rows)
