"""Single authorization/business layer. SQLite is an OFFLINE transactional model.
Production store, distributed fencing and execution worker deployment remain gated.
Reads never reconcile, write journals, or acquire durable reservations.
"""
from dataclasses import dataclass, field
from contextlib import contextmanager
from typing import Protocol
import json, sqlite3, time, uuid, secrets
from .contracts import *
from .aws import compile_ec2

class Denied(Exception): pass
class Unconfigured(Denied): pass
class Conflict(Denied): pass

def ident(prefix): return prefix+'_'+uuid.uuid4().hex

@dataclass(frozen=True)
class RoleTemplate:
    logical_role: str
    account_id: str
    region: str
    allowed_instance_arns: tuple[str,...]
    allowed_actions: tuple[str,...]
    admin_tags: dict = field(default_factory=dict)

@dataclass(frozen=True)
class Entitlement:
    owner_id: str
    subject: str
    client_id: str
    logical_roles: tuple[str,...]
    operations: tuple[str,...] = ('request','read','enroll','lease','redeem')

class EnrollmentProvider(Protocol):
    name: str
    def verify(self, evidence: str, principal, grant: dict, now: int) -> dict: ...

class ExecutionProvider(Protocol):
    def apply(self, manifest: dict) -> dict: ...
    def observe(self, manifest: dict) -> dict: ...

class CredentialProvider(Protocol):
    def issue(self, grant: dict, run: dict, now: int, expires_at: int): ...

class Service:
    def __init__(self,path,*,templates=(),entitlements=(),owner_id='',browser_client_id='',
                 executor=None,enrollment=None,credentials=None,clock=time.time,offline_mode=False):
        self.path=str(path); self.clock=clock; self.templates={x.logical_role:x for x in templates}
        self.entitlements=tuple(entitlements); self.owner_id=owner_id; self.browser_client_id=browser_client_id
        self.executor=executor; self.enrollment=enrollment; self.credentials=credentials
        self.offline_mode=offline_mode; self.run_guard=None
        if not offline_mode and any((executor,enrollment,credentials)):
            raise Unconfigured('production persistence and distributed fencing adapter are not installed')
        with self.tx() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS roles(name TEXT PRIMARY KEY,generation INTEGER,grant_id TEXT,pending TEXT);
            CREATE TABLE IF NOT EXISTS requests(id TEXT,revision INTEGER,owner TEXT,subject TEXT,client TEXT,
              manifest TEXT,digest TEXT,state TEXT,operation_id TEXT,PRIMARY KEY(id,revision));
            CREATE TABLE IF NOT EXISTS decisions(id TEXT,revision INTEGER,digest TEXT,choice TEXT,
              authentication_id TEXT,PRIMARY KEY(id,revision));
            CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,request_id TEXT,revision INTEGER,state TEXT,detail TEXT);
            CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY,owner TEXT,subject TEXT,client TEXT,role TEXT,
              generation INTEGER,state TEXT,manifest TEXT,operation_id TEXT,physical_name TEXT,predecessor TEXT);
            CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,grant_id TEXT,subject TEXT,client TEXT,provider TEXT,expires INTEGER,label TEXT);
            CREATE TABLE IF NOT EXISTS leases(handle TEXT PRIMARY KEY,grant_id TEXT,run_id TEXT,subject TEXT,client TEXT,
              redeem_before INTEGER,maximum_expiration INTEGER,state TEXT);
            CREATE TABLE IF NOT EXISTS idempotency(actor TEXT,key TEXT,payload TEXT,result TEXT,PRIMARY KEY(actor,key));
            CREATE TABLE IF NOT EXISTS journal(seq INTEGER PRIMARY KEY AUTOINCREMENT,at INTEGER,event TEXT,object_id TEXT,detail TEXT);
            CREATE TRIGGER IF NOT EXISTS frozen_manifest BEFORE UPDATE OF manifest,digest ON requests BEGIN SELECT RAISE(ABORT,'immutable manifest'); END;
            CREATE TRIGGER IF NOT EXISTS frozen_decisions BEFORE UPDATE ON decisions BEGIN SELECT RAISE(ABORT,'immutable decision'); END;
            CREATE TRIGGER IF NOT EXISTS no_delete_decisions BEFORE DELETE ON decisions BEGIN SELECT RAISE(ABORT,'immutable decision'); END;
            CREATE TRIGGER IF NOT EXISTS frozen_journal BEFORE UPDATE ON journal BEGIN SELECT RAISE(ABORT,'append only'); END;
            CREATE TRIGGER IF NOT EXISTS no_delete_journal BEFORE DELETE ON journal BEGIN SELECT RAISE(ABORT,'append only'); END;
            ''')
            for name in self.templates:
                db.execute('INSERT OR IGNORE INTO roles VALUES (?,0,NULL,NULL)',(name,))

    @contextmanager
    def tx(self):
        db=sqlite3.connect(self.path,timeout=10); db.row_factory=sqlite3.Row
        try:
            db.execute('BEGIN IMMEDIATE'); yield db; db.commit()
        except BaseException: db.rollback(); raise
        finally: db.close()

    @contextmanager
    def query(self):
        db=sqlite3.connect('file:'+self.path+'?mode=ro',uri=True); db.row_factory=sqlite3.Row
        try:
            db.execute('PRAGMA query_only=ON'); yield db
        finally: db.close()

    def now(self): return int(self.clock())
    def event(self,db,event,obj,detail=''):
        db.execute('INSERT INTO journal(at,event,object_id,detail) VALUES (?,?,?,?)',(self.now(),event,obj,detail))
    def human(self,p):
        if not self.owner_id or not self.browser_client_id or p.actor_kind!='human_browser' or p.owner_id!=self.owner_id or p.client_id!=self.browser_client_id:
            raise Denied('verified human browser approval required')
    def authorize(self,p,op,role):
        if p.actor_kind=='human_browser':
            self.human(p)
            if op!='read': raise Denied('browser may only review and decide')
            return
        if not any(e.owner_id==p.owner_id and e.subject==p.subject and e.client_id==p.client_id and role in e.logical_roles and op in e.operations for e in self.entitlements):
            raise Denied('app-owned client grant is missing')
    def own(self,p,row,op='read'):
        m=json.loads(row['manifest']); self.authorize(p,op,m['logical_role'])
        if row['owner']!=p.owner_id: raise Denied('resource unavailable')
        if p.actor_kind!='human_browser' and (row['subject']!=p.subject or row['client']!=p.client_id):
            raise Denied('resource unavailable')
        return m
    def actor(self,p): return canonical([p.owner_id,p.subject,p.client_id])
    def replay(self,db,p,key,payload):
        row=db.execute('SELECT * FROM idempotency WHERE actor=? AND key=?',(self.actor(p),key)).fetchone()
        if row:
            if row['payload']!=digest(payload): raise Conflict('idempotency key reused with different input')
            return json.loads(row['result'])
    def remember(self,db,p,key,payload,result):
        db.execute('INSERT INTO idempotency VALUES (?,?,?,?)',(self.actor(p),key,digest(payload),canonical(result)))
    def row(self,db,rid,rev=None):
        row=db.execute('SELECT * FROM requests WHERE id=? '+('AND revision=?' if rev else 'ORDER BY revision DESC LIMIT 1'),(rid,rev) if rev else (rid,)).fetchone()
        if not row: raise Denied('resource unavailable')
        if digest(json.loads(row['manifest']))!=row['digest']: raise Denied('manifest integrity failure')
        return row
    def view(self,row):
        return RequestView(request_id=row['id'],revision=row['revision'],digest=row['digest'],state=row['state'],manifest=json.loads(row['manifest']),operation_id=row['operation_id'])

    def submit(self,p,data:RequestInput,rid=None,expected_revision=None):
        self.authorize(p,'request',data.logical_role)
        t=self.templates.get(data.logical_role)
        if not t: raise Denied('unknown administrator role template')
        s=data.scope.model_dump()
        if len(s['actions'])!=len(set(s['actions'])) or len(s['instance_arns'])!=len(set(s['instance_arns'])):
            raise Denied('duplicate scope members')
        s={'actions':sorted(s['actions']),'instance_arns':sorted(s['instance_arns'])}
        if not set(s['actions'])<=set(t.allowed_actions) or not set(s['instance_arns'])<=set(t.allowed_instance_arns):
            raise Denied('scope exceeds administrator ceiling')
        policy=compile_ec2(s,t.account_id,t.region,not_after=data.not_after,admin_tags=t.admin_tags)
        now=self.now()
        if data.access=='temporary' and (data.effective_at<now or data.not_after-data.effective_at<960):
            raise Denied('temporary window must start in the future and last at least 960 seconds (900-second AWS minimum plus 60-second redemption allowance)')
        if data.effective_at is not None and data.effective_at<now: raise Denied('requested start has passed')
        payload={'command':'submit','request':data.model_dump(),'request_id':rid,'expected_revision':expected_revision}
        with self.tx() as db:
            replay=self.replay(db,p,data.idempotency_key,payload)
            if replay: return self.view(self.row(db,replay['id'],replay['revision']))
            role=db.execute('SELECT * FROM roles WHERE name=?',(data.logical_role,)).fetchone()
            if role['pending']: raise Conflict('role has an unresolved approved transition')
            if role['generation']!=data.expected_generation: raise Conflict('stale logical role generation')
            old=db.execute('SELECT * FROM grants WHERE id=?',(role['grant_id'],)).fetchone() if role['grant_id'] else None
            if old and old['state'] not in ('active','expired','superseded','stopped'): raise Conflict('role is quarantined or transitioning')
            restoration=json.loads(old['manifest'])['scope'] if old and data.access=='temporary' else None
            if old and json.loads(old['manifest'])['access']=='temporary' and old['state']!='stopped':
                raise Conflict('finish approved temporary restoration before another change')
            rev=1
            if rid:
                prior=self.row(db,rid); self.own(p,prior,'request')
                if prior['revision']!=expected_revision or prior['state']!='awaiting_owner': raise Conflict('revision is no longer editable')
                if json.loads(prior['manifest'])['logical_role']!=data.logical_role: raise Conflict('cannot change logical role in a revision')
                rev=prior['revision']+1; db.execute("UPDATE requests SET state='superseded' WHERE id=? AND revision=?",(rid,rev-1))
            rid=rid or ident('req'); generation=role['generation']+1
            physical='broker-'+data.logical_role[:44]+'-'+uuid.uuid4().hex[:12]
            m={'contract':'broker.ec2.v1','request_id':rid,'revision':rev,'logical_role':data.logical_role,
               'generation':generation,'baseline_generation':role['generation'],'predecessor_grant_id':role['grant_id'],
               'scope':s,'policy':policy,'account_id':t.account_id,'region':t.region,'admin_tags':t.admin_tags,
               'reason':data.reason,'access':data.access,'not_after':data.not_after,'effective_at':data.effective_at,
               'physical_role_name':physical,'physical_role_arn':f'arn:aws:iam::{t.account_id}:role/{physical}',
               'change_mode':'new_physical_revision','existing_external_role_adoption':False,
               'on_approval':'stop predecessor issuance immediately; wait for all outstanding leases',
               'restoration':{'scope':restoration,'at':data.not_after,'mode':'new_physical_revision'} if restoration else None,
               'on_expiry':'deny issuance; absolute AWS session-policy cutoff; no instant revocation claim',
               'created_at':now,'session_seconds':900,'offline':self.offline_mode}
            if restoration:
                restore_physical='broker-'+data.logical_role[:44]+'-'+uuid.uuid4().hex[:12]
                restored={**m,'request_id':rid+'-restore','revision':1,'generation':generation+1,'baseline_generation':generation,
                    'scope':restoration,'policy':compile_ec2(restoration,t.account_id,t.region,admin_tags=t.admin_tags),
                    'access':'ongoing','not_after':None,'effective_at':data.not_after,'physical_role_name':restore_physical,
                    'physical_role_arn':f'arn:aws:iam::{t.account_id}:role/{restore_physical}',
                    'reason':'Restore exactly the previous ongoing scope after the approved temporary window',
                    'restoration':None,'predecessor_grant_id':'$temporary_grant','restoration_of':rid}
                m['restoration']=restored
            db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,NULL)',(rid,rev,p.owner_id,p.subject,p.client_id,canonical(m),digest(m),'awaiting_owner'))
            self.event(db,'submitted',rid,digest(m)); self.remember(db,p,data.idempotency_key,payload,{'id':rid,'revision':rev})
            return self.view(self.row(db,rid,rev))

    def request(self,p,rid):
        with self.query() as db:
            row=self.row(db,rid); self.own(p,row); return self.view(row)
    def requests(self,p):
        self.authorize_any_read(p)
        with self.query() as db:
            rows=db.execute('SELECT * FROM requests r WHERE revision=(SELECT MAX(revision) FROM requests WHERE id=r.id) ORDER BY id').fetchall()
            visible=[]
            for row in rows:
                try: self.own(p,row); visible.append(self.view(row))
                except Denied: pass
            return RequestList(requests=visible)

    def decide(self,p,rid,revision,expected_digest,choice):
        self.human(p)
        if choice not in ('approve','reject'): raise Denied('unknown decision')
        with self.tx() as db:
            row=self.row(db,rid); m=self.own(p,row)
            if row['revision']!=revision or row['digest']!=expected_digest or row['state']!='awaiting_owner': raise Conflict('exact current undecided revision required')
            role=db.execute('SELECT * FROM roles WHERE name=?',(m['logical_role'],)).fetchone()
            if role['generation']!=m['baseline_generation'] or role['pending']: raise Conflict('stale or reserved role revision')
            if choice=='approve':
                latest=db.execute('SELECT MAX(maximum_expiration) FROM leases WHERE grant_id=?',(role['grant_id'],)).fetchone()[0] or self.now()
                if m['effective_at'] is not None and max(self.now(),latest)>m['effective_at']: raise Conflict('requested start cannot be met; revise window')
                op=ident('op'); db.execute('INSERT INTO operations VALUES (?,?,?,?,?)',(op,rid,revision,'approved','execution adapter required; lease drain enforced'))
                db.execute('UPDATE roles SET pending=? WHERE name=?',(rid,m['logical_role']))
                if role['grant_id']: db.execute("UPDATE grants SET state='draining' WHERE id=?",(role['grant_id'],))
            else: op=None
            db.execute('INSERT INTO decisions VALUES (?,?,?,?,?)',(rid,revision,expected_digest,choice,p.authentication_id))
            db.execute('UPDATE requests SET state=?,operation_id=? WHERE id=? AND revision=?',('approved' if choice=='approve' else 'rejected',op,rid,revision))
            self.event(db,'human_'+choice,rid,expected_digest)
            return self.view(self.row(db,rid))

    def execute(self,rid):
        """Private command/worker only. Never exposed by REST/MCP. Default denies."""
        if self.executor is None: raise Unconfigured('permission execution provider is not installed')
        with self.tx() as db:
            row=self.row(db,rid); m=json.loads(row['manifest'])
            if row['state']=='active': return self.operation_unchecked(db,row['operation_id'])
            if row['state'] not in ('approved','draining'): raise Conflict('not safely executable; explicit reconciliation required')
            dec=db.execute('SELECT * FROM decisions WHERE id=? AND revision=?',(rid,row['revision'])).fetchone()
            if not dec or dec['choice']!='approve' or dec['digest']!=row['digest']: raise Denied('frozen approval missing')
            role=db.execute('SELECT * FROM roles WHERE name=?',(m['logical_role'],)).fetchone()
            if role['pending']!=rid or role['generation']!=m['baseline_generation']: raise Conflict('generation or reservation mismatch')
            predecessor=db.execute('SELECT state FROM grants WHERE id=?',(role['grant_id'],)).fetchone() if role['grant_id'] else None
            if predecessor and predecessor['state']=='stopped': raise Conflict('explicit issuance stop requires cancel and fresh human approval')
            drain=db.execute('SELECT MAX(maximum_expiration) FROM leases WHERE grant_id=?',(role['grant_id'],)).fetchone()[0] or 0
            due=max(drain,m['effective_at'] or 0)
            if self.now()<due:
                db.execute("UPDATE requests SET state='draining' WHERE id=? AND revision=?",(rid,row['revision']))
                db.execute("UPDATE operations SET state='draining',detail=? WHERE id=?",('waiting until '+str(due),row['operation_id']))
                return self.operation_unchecked(db,row['operation_id'])
            if m['access']=='temporary' and self.now()!=m['effective_at']:
                raise Conflict('exact approved temporary start missed; fresh human revision required')
            db.execute("UPDATE requests SET state='applying' WHERE id=? AND revision=?",(rid,row['revision']))
            db.execute("UPDATE operations SET state='applying',detail='provider outcome pending' WHERE id=?",(row['operation_id'],))
            self.event(db,'write_intent',rid,row['digest'])
        try: receipt=self.executor.apply(m)
        except Exception:
            with self.tx() as db:
                db.execute("UPDATE requests SET state='needs_review' WHERE id=? AND revision=?",(rid,row['revision']))
                db.execute("UPDATE operations SET state='needs_review',detail='provider outcome unknown; reservation retained' WHERE id=?",(row['operation_id'],))
            raise Denied('provider outcome unknown; role quarantined') from None
        return self.finalize(rid,receipt)

    def finalize(self,rid,receipt):
        with self.tx() as db:
            row=self.row(db,rid); m=json.loads(row['manifest'])
            if row['state']=='active': return self.operation_unchecked(db,row['operation_id'])
            if row['state'] not in ('applying','needs_review'): raise Conflict('unexpected execution state')
            if receipt != {'manifest_digest':row['digest'],'physical_role_name':m['physical_role_name'],'verified':True}:
                db.execute("UPDATE requests SET state='needs_review' WHERE id=? AND revision=?",(rid,row['revision']))
                db.execute("UPDATE operations SET state='needs_review',detail='provider identity or policy was not verified' WHERE id=?",(row['operation_id'],))
                self.event(db,'unknown_receipt',rid)
                return OperationView(operation_id=row['operation_id'],state='needs_review',detail='provider identity or policy was not verified')
            if row['state'] not in ('applying','needs_review'): raise Conflict('unexpected execution state')
            role=db.execute('SELECT * FROM roles WHERE name=?',(m['logical_role'],)).fetchone()
            if role['pending']!=rid or role['generation']!=m['baseline_generation']: raise Conflict('reservation changed; quarantine')
            predecessor=db.execute('SELECT state FROM grants WHERE id=?',(role['grant_id'],)).fetchone() if role['grant_id'] else None
            if predecessor and predecessor['state']=='stopped':
                db.execute("UPDATE requests SET state='needs_review' WHERE id=? AND revision=?",(rid,row['revision']))
                db.execute("UPDATE operations SET state='needs_review',detail='issuance stopped during provider attempt; reservation retained' WHERE id=?",(row['operation_id'],))
                return self.operation_unchecked(db,row['operation_id'])
            if m['not_after'] is not None and self.now()>=m['not_after']: raise Conflict('grant expired during execution; quarantine')
            gid=ident('grant')
            db.execute('INSERT INTO grants VALUES (?,?,?,?,?,?,?,?,?,?,?)',(gid,row['owner'],row['subject'],row['client'],m['logical_role'],m['generation'],'active',row['manifest'],row['operation_id'],m['physical_role_name'],role['grant_id']))
            if role['grant_id']: db.execute("UPDATE grants SET state='superseded' WHERE id=?",(role['grant_id'],))
            db.execute('UPDATE roles SET generation=?,grant_id=?,pending=NULL WHERE name=?',(m['generation'],gid,m['logical_role']))
            db.execute("UPDATE requests SET state='active' WHERE id=? AND revision=?",(rid,row['revision']))
            db.execute("UPDATE operations SET state='active',detail='verified non-live revision active' WHERE id=?",(row['operation_id'],))
            self.event(db,'activated',gid,row['digest']); return self.operation_unchecked(db,row['operation_id'])

    def reconcile(self,rid):
        if self.executor is None: raise Unconfigured('execution observation provider is not installed')
        with self.query() as db:
            row=self.row(db,rid); m=json.loads(row['manifest'])
            if row['state'] not in ('needs_review','applying'): raise Conflict('not an uncertain execution')
        return self.finalize(rid,self.executor.observe(m))

    def operation_unchecked(self,db,oid):
        row=db.execute('SELECT * FROM operations WHERE id=?',(oid,)).fetchone()
        return OperationView(operation_id=row['id'],state=row['state'],detail=row['detail'])
    def operation(self,p,oid):
        with self.query() as db:
            row=db.execute('SELECT * FROM operations WHERE id=?',(oid,)).fetchone()
            if not row: raise Denied('resource unavailable')
            self.own(p,self.row(db,row['request_id'],row['revision']))
            return self.operation_unchecked(db,oid)

    def grant_row(self,db,p,gid,op='read'):
        row=db.execute('SELECT * FROM grants WHERE id=?',(gid,)).fetchone()
        if not row: raise Denied('resource unavailable')
        self.own(p,row,op); return row
    def grant_view(self,row):
        m=json.loads(row['manifest']); state=row['state']
        if state=='active' and m['not_after'] is not None and self.now()>=m['not_after']: state='expired'
        return GrantView(grant_id=row['id'],logical_role=row['role'],generation=row['generation'],state=state,scope=Scope(**m['scope']),not_after=m['not_after'],physical_role_name=row['physical_name'],predecessor_grant_id=row['predecessor'],operation_id=row['operation_id'])
    def grants(self,p):
        self.authorize_any_read(p)
        with self.query() as db:
            visible=[]
            for row in db.execute('SELECT * FROM grants ORDER BY role,generation'):
                try: self.own(p,row); visible.append(self.grant_view(row))
                except Denied: pass
            return GrantList(grants=visible)
    def active(self,row):
        m=json.loads(row['manifest'])
        if row['state']!='active' or (m['not_after'] is not None and self.now()>=m['not_after']): raise Denied('grant does not permit new access')
        return m

    def enroll(self,p,data:RunEnrollmentInput):
        if self.enrollment is None: raise Unconfigured('trusted enrollment provider is not installed')
        with self.tx() as db:
            row=self.grant_row(db,p,data.grant_id,'enroll'); m=self.active(row)
            claim=self.enrollment.verify(data.evidence,p,dict(row),self.now())
            if claim.get('grant_id')!=row['id'] or claim.get('subject')!=p.subject or claim.get('client_id')!=p.client_id or type(claim.get('expires_at')) is not int or claim['expires_at']<=self.now():
                raise Denied('trusted run assertion does not bind caller and grant')
            rid=ident('run'); expiry=min(claim['expires_at'],m['not_after'] or claim['expires_at'])
            db.execute('INSERT INTO runs VALUES (?,?,?,?,?,?,?)',(rid,row['id'],p.subject,p.client_id,self.enrollment.name,expiry,data.environment_label))
            self.event(db,'run_enrolled',rid,self.enrollment.name)
            return RunIdentity(run_id=rid,grant_id=row['id'],provider=self.enrollment.name,expires_at=expiry,environment_label=data.environment_label)

    def lease(self,p,data:LeaseInput,*,key_bound=False):
        if self.credentials is None or self.enrollment is None: raise Unconfigured('credential issuance and trusted enrollment are not installed')
        with self.tx() as db:
            payload={'command':'lease',**data.model_dump()}; replay=self.replay(db,p,data.idempotency_key,payload)
            if replay: return CredentialLease(**replay)
            row=self.grant_row(db,p,data.grant_id,'lease'); m=self.active(row)
            run=db.execute('SELECT * FROM runs WHERE id=?',(data.run_id,)).fetchone()
            if not run or run['grant_id']!=row['id'] or run['subject']!=p.subject or run['client']!=p.client_id: raise Denied('run does not belong to caller and grant')
            if run['provider']=='coordinator-authorized-key':
                if not key_bound or self.run_guard is None: raise Denied('fresh worker proof is required')
                self.run_guard(run['id'])
            maximum=self.now()+960
            if maximum>run['expires'] or (m['not_after'] is not None and maximum>m['not_after']): raise Denied('less than 900-second AWS minimum plus redemption allowance remains')
            handle=ident('use'); result=CredentialLease(handle=handle,grant_id=row['id'],run_id=run['id'],redeem_before=self.now()+60,maximum_expiration=maximum)
            db.execute('INSERT INTO leases VALUES (?,?,?,?,?,?,?,?)',(handle,row['id'],run['id'],p.subject,p.client_id,result.redeem_before,maximum,'prepared'))
            self.event(db,'lease_reserved',row['id'],'credential_process delivery only')
            self.remember(db,p,data.idempotency_key,payload,result.model_dump()); return result

    def redeem(self,p,handle,*,key_bound=False):
        if self.credentials is None: raise Unconfigured('credential provider is not installed')
        with self.tx() as db:
            lease=db.execute('SELECT * FROM leases WHERE handle=?',(handle,)).fetchone()
            if not lease or lease['subject']!=p.subject or lease['client']!=p.client_id: raise Denied('credential-use handle unavailable')
            row=self.grant_row(db,p,lease['grant_id'],'redeem'); m=self.active(row)
            if lease['state']!='prepared' or self.now()>=lease['redeem_before']: raise Denied('credential-use handle expired or consumed')
            run=db.execute('SELECT * FROM runs WHERE id=?',(lease['run_id'],)).fetchone()
            if run['provider']=='coordinator-authorized-key':
                if not key_bound or self.run_guard is None: raise Denied('fresh worker proof is required')
                self.run_guard(run['id'])
            if self.now()+900>run['expires']: raise Denied('run expired')
            db.execute("UPDATE leases SET state='consumed' WHERE handle=?",(handle,))
            self.event(db,'credential_use',row['id'],'secrets omitted')
            failed=False
            try: envelope=self.credentials.issue(dict(row),dict(run),self.now(),self.now()+900)
            except Exception: failed=True
        if failed: raise Denied('credential provider unavailable; reserved lease retained until maximum expiration') from None
        return envelope


    def restore(self,temporary_grant_id):
        """Private scheduled command for an exact restoration embedded in human approval."""
        if self.executor is None: raise Unconfigured('execution provider is not installed')
        with self.tx() as db:
            grant=db.execute('SELECT * FROM grants WHERE id=?',(temporary_grant_id,)).fetchone()
            if not grant: raise Denied('resource unavailable')
            if grant['state']=='stopped': raise Denied('explicit issuance stop cancels automatic restoration; fresh human approval required')
            m=json.loads(grant['manifest']); restored=m.get('restoration')
            if not restored or self.now()<m['not_after']: raise Conflict('no restoration due')
            role=db.execute('SELECT * FROM roles WHERE name=?',(grant['role'],)).fetchone()
            if role['grant_id']!=temporary_grant_id: raise Conflict('temporary revision is no longer current')
            parent=self.row(db,m['request_id'],m['revision'])
            decision=db.execute('SELECT * FROM decisions WHERE id=? AND revision=?',(parent['id'],parent['revision'])).fetchone()
            if not decision or decision['choice']!='approve' or decision['digest']!=parent['digest']: raise Denied('restoration approval missing')
            rid=restored['request_id']
            existing=db.execute('SELECT * FROM requests WHERE id=?',(rid,)).fetchone()
            if not existing:
                if role['pending']: raise Conflict('role has an unresolved transition')
                op=ident('op')
                db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?)',(rid,1,grant['owner'],grant['subject'],grant['client'],canonical(restored),digest(restored),'approved',op))
                db.execute('INSERT INTO decisions VALUES (?,?,?,?,?)',(rid,1,digest(restored),'approve',decision['authentication_id']))
                db.execute('INSERT INTO operations VALUES (?,?,?,?,?)',(op,rid,1,'approved','exact restoration already included in human manifest'))
                db.execute('UPDATE roles SET pending=? WHERE name=?',(rid,role['name']))
                db.execute("UPDATE grants SET state='draining' WHERE id=?",(temporary_grant_id,))
                self.event(db,'restoration_due',rid,parent['digest'])
        return self.execute(rid)

    def stop_grant(self,p,gid):
        """Human command: stop new issuance; outstanding AWS credentials retain cutoff."""
        self.human(p)
        with self.tx() as db:
            row=self.grant_row(db,p,gid)
            db.execute("UPDATE grants SET state='stopped' WHERE id=?",(gid,))
            self.event(db,'issuance_stopped',gid,'outstanding AWS leases are not instantly revoked')
            return self.grant_view(db.execute('SELECT * FROM grants WHERE id=?',(gid,)).fetchone())

    def coordinator_current(self,gid):
        with self.query() as db:
            row=db.execute('SELECT * FROM grants WHERE id=?',(gid,)).fetchone()
            if not row: raise Denied('resource unavailable')
            m=json.loads(row['manifest'])
            return {'grant_id':gid,'revision':m['revision'],'digest':digest(m),'roles':[row['role']],
                    'not_after':m['not_after'],'state':self.grant_view(row).state,
                    'owner_id':row['owner'],'subject':row['subject'],'client_id':row['client']}

    def enrollment_binding(self,p,gid):
        with self.query() as db: self.grant_row(db,p,gid,'enroll')
        current=self.coordinator_current(gid)
        return {k:current[k] for k in ('grant_id','revision','digest','roles','not_after')}

    def attach_trusted_run(self,summary):
        """Internal bridge; rechecks current trusted authority before bounded renewal sync."""
        if self.run_guard is None: raise Unconfigured('trusted run observation is not installed')
        with self.tx() as db:
            verified=self.run_guard(summary['run_id'])
            for key in ('run_id','owner_id','subject','client_id','grant_binding','expires_at','maximum_expires_at'):
                if summary.get(key)!=verified.get(key): raise Denied('stale or forged run summary')
            binding=verified['grant_binding']; current=self.coordinator_current(binding['grant_id'])
            if current['state']!='active' or any(current[k]!=binding[k] for k in binding): raise Denied('grant changed')
            if any(current[k]!=verified[k] for k in ('owner_id','subject','client_id')): raise Denied('run caller mismatch')
            old=db.execute('SELECT * FROM runs WHERE id=?',(verified['run_id'],)).fetchone()
            identity=(binding['grant_id'],verified['subject'],verified['client_id'],'coordinator-authorized-key')
            if old:
                if (old['grant_id'],old['subject'],old['client'],old['provider'])!=identity: raise Denied('run identity collision')
                if old['expires']!=verified['expires_at']:
                    db.execute('UPDATE runs SET expires=? WHERE id=?',(verified['expires_at'],verified['run_id']))
                    self.event(db,'coordinator_run_renewed',verified['run_id'],'verified bounded renewal')
            else:
                db.execute('INSERT INTO runs VALUES (?,?,?,?,?,?,?)',(verified['run_id'],*identity,verified['expires_at'],'unsigned labels are not attestation'))
                self.event(db,'coordinator_run_attached',verified['run_id'],'key-bound proof verified; no machine attestation')

    def authorize_any_read(self,p):
        if p.actor_kind=='human_browser': return self.human(p)
        if not any(e.owner_id==p.owner_id and e.subject==p.subject and e.client_id==p.client_id and 'read' in e.operations for e in self.entitlements):
            raise Denied('app-owned client grant is missing')


    def cancel_pending(self,p,rid,revision,expected_digest):
        """Human exact-revision cancel BEFORE any write. Unknown attempts stay reserved."""
        self.human(p)
        with self.tx() as db:
            row=self.row(db,rid);m=self.own(p,row)
            if row['revision']!=revision or row['digest']!=expected_digest: raise Conflict('exact current revision required')
            if row['state'] not in ('awaiting_owner','approved','draining'): raise Conflict('cannot cancel an attempted or uncertain provider transition')
            attempted=db.execute("SELECT 1 FROM journal WHERE object_id=? AND event='write_intent'",(rid,)).fetchone()
            if attempted: raise Conflict('durable write intent must remain quarantined')
            role=db.execute('SELECT * FROM roles WHERE name=?',(m['logical_role'],)).fetchone()
            if role['pending'] not in (None,rid): raise Conflict('another role transition owns reservation')
            db.execute("UPDATE requests SET state='cancelled' WHERE id=? AND revision=?",(rid,revision))
            if role['pending']==rid:
                db.execute('UPDATE roles SET pending=NULL WHERE name=?',(role['name'],))
                if role['grant_id']: db.execute("UPDATE grants SET state='stopped' WHERE id=?",(role['grant_id'],))
            if row['operation_id']: db.execute("UPDATE operations SET state='cancelled',detail='cancelled before provider write; predecessor issuance remains stopped' WHERE id=?",(row['operation_id'],))
            self.event(db,'human_cancelled_before_write',rid,expected_digest)
            return self.view(self.row(db,rid))
