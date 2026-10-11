"""Regression verification independent of candidate test implementation."""
import asyncio,dataclasses,io,json,logging,sqlite3,tempfile,unittest
from fastapi.testclient import TestClient
from independent_controls import Controls
from integration.fixtures import *
from integration.contracts import *
from integration.enrollment import *
from integration.providers import AWSRuntimeCredentials,PinnedRevision
from integration.aws import RoleExpectation,REVISION_POLICY_NAME
from integration.service import Denied,Conflict,Service,RoleTemplate,Entitlement
from integration.http import create_app,HTTPConfig
class Fixed(Controls):
 def test_stop_is_not_undone_by_temporary_restoration(self):
  _,old=self.active();r=self.s.submit(ACTOR,self.data(expected_generation=1,access='temporary',effective_at=self.now,not_after=self.now+1800,idempotency_key='independent-0002'));self.s.decide(HUMAN,r.request_id,1,r.digest,'approve');self.s.execute(r.request_id);g=self.s.grants(ACTOR).grants[-1]
  self.s.stop_grant(HUMAN,g.grant_id);self.now+=1800
  with self.assertRaises(Denied):self.s.restore(g.grant_id)
  self.assertFalse(any(g.state=='active' for g in self.s.grants(ACTOR).grants))
 def test_invalid_receipt_durable_state_and_stale_finalization(self):
  r=self.s.submit(ACTOR,self.data());self.s.decide(HUMAN,r.request_id,1,r.digest,'approve');original=self.s.executor.apply
  self.s.executor.apply=lambda m:(original(m),{'verified':False})[1]
  op=self.s.execute(r.request_id);self.assertEqual(op.state,'needs_review');self.assertEqual(self.s.operation(ACTOR,op.operation_id).state,'needs_review')
  self.s.reconcile(r.request_id);before=self.dump();self.s.finalize(r.request_id,{'verified':False});self.assertEqual(before,self.dump())
 def test_rpc_reflections_scrubbed_and_logs_quiet(self):
  marker='INDEPENDENT_SYNTHETIC_PRIVATE_MARKER';data=self.data().model_dump();data['owner']=marker
  cases=[('tools/call',{'name':'request_permission_scope','arguments':{'request':data}}),('tools/call',{'name':marker,'arguments':{}}),('resources/read',{'uri':'https://invalid.example/'+marker}),('prompts/get',{'name':marker}),('initialize',{'clientInfo':marker})]
  capture=io.StringIO();handler=logging.StreamHandler(capture);logging.getLogger().addHandler(handler)
  try:
   with self.client() as c:
    for method,params in cases:
     r=c.post('/mcp',headers={'Authorization':'Bearer OFFLINE-ONLY','Accept':'application/json, text/event-stream'},json={'jsonrpc':'2.0','id':1,'method':method,'params':params});self.assertNotIn(marker,r.text)
   self.assertNotIn(marker,capture.getvalue())
  finally:logging.getLogger().removeHandler(handler)
 def test_missed_activation_recovers_only_by_human_cancel(self):
  r=self.s.submit(ACTOR,self.data(access='temporary',effective_at=self.now+10,not_after=self.now+1810));self.s.decide(HUMAN,r.request_id,1,r.digest,'approve');self.now+=11
  with self.assertRaises(Conflict):self.s.execute(r.request_id)
  with self.assertRaises(Denied):self.s.cancel_pending(ACTOR,r.request_id,1,r.digest)
  self.s.cancel_pending(HUMAN,r.request_id,1,r.digest)
  r2=self.s.submit(ACTOR,self.data(idempotency_key='independent-0002'));self.s.decide(HUMAN,r2.request_id,1,r2.digest,'approve');self.s.execute(r2.request_id)
  self.assertEqual(self.s.grants(ACTOR).grants[0].state,'active')
 def test_cancel_never_frees_unknown_write(self):
  r=self.s.submit(ACTOR,self.data());self.s.decide(HUMAN,r.request_id,1,r.digest,'approve');self.s.executor.timeout=True
  with self.assertRaises(Denied):self.s.execute(r.request_id)
  before=self.dump()
  with self.assertRaises(Conflict):self.s.cancel_pending(HUMAN,r.request_id,1,r.digest)
  self.assertEqual(before,self.dump())
 def test_pinned_same_policy_other_arn_never_reaches_sts(self):
  _,g=self.active()
  with self.s.query() as db:grant=dict(db.execute('select * from grants').fetchone())
  m=json.loads(grant['manifest']);name='unapproved-physical-name';rid='AROA1234567890EXAMPLE1'
  exp=RoleExpectation(name,'arn:aws:iam::111122223333:role/'+name,rid,{'Statement':[]},{'arn':'arn:aws:iam::111122223333:policy/ceiling','version_id':'v1','document':m['policy']},{REVISION_POLICY_NAME:m['policy']},{})
  pin=PinnedRevision(g.grant_id,digest(m),rid,exp.fingerprint,exp)
  class STS:
   calls=0
   def issue(self,*args,**kwargs):self.calls+=1;return None
  sts=STS();p=AWSRuntimeCredentials(sts,{g.physical_role_name:pin})
  with self.assertRaises(Denied):p.issue(grant,{'id':'run_test','grant_id':g.grant_id,'expires':self.now+1800},self.now,self.now+900)
  self.assertEqual(sts.calls,0)
 def test_aws_lifetime_boundaries_reject_before_admission(self):
  from pydantic import ValidationError
  for seconds in (900,959):
   with self.assertRaises(Denied):self.s.submit(ACTOR,self.data(access='temporary',effective_at=self.now,not_after=self.now+seconds,idempotency_key='independent-'+str(seconds)))
   with self.assertRaises(ValidationError):EnrollmentPrepareInput(grant_id='synthetic',public_jwk={},lifetime=seconds,idempotency_key='independent-lifetime')
  r=self.s.submit(ACTOR,self.data(access='temporary',effective_at=self.now,not_after=self.now+960));self.s.decide(HUMAN,r.request_id,1,r.digest,'approve');self.s.execute(r.request_id);g=self.s.grants(ACTOR).grants[0];run=self.s.enroll(ACTOR,RunEnrollmentInput(grant_id=g.grant_id,evidence='OFFLINE-ONLY'))
  lease=self.s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run.run_id,idempotency_key='independent-boundary'));self.assertEqual(lease.maximum_expiration,self.now+960)
 def test_run_renewal_current_guard_syncs_and_rejects_forgery(self):
  _,g=self.active();e=CoordinatorEnrollment(self.s.path,configured=True,offline_mode=True,trust=(StandingTrust(ACTOR.owner_id,ACTOR.subject,ACTOR.client_id,ACTOR.authentication_id,'independent-connection'),),active_grant=self.s.coordinator_current,redeem_url=self.origin+'/enrollment/redeem',clock=lambda:self.now);self.s.run_guard=e.get_run
  key,pub=fresh_key();binding=self.s.enrollment_binding(ACTOR,g.grant_id);p=e.prepare(ACTOR,pub,binding,1200,'independent-enroll');run=e.redeem(p['enrollment_id'],make_proof(key,pub,'POST',e.redeem_url,p['challenge'],binding,enrollment_id=p['enrollment_id'],clock=lambda:self.now,offline_mode=True));self.s.attach_trusted_run(run)
  self.now+=100;nonce=e.issue_nonce(run['run_id']);proof=make_proof(key,pub,'POST',self.origin+'/run/renew',nonce,binding,run_id=run['run_id'],clock=lambda:self.now,offline_mode=True);renewed=e.renew(run['run_id'],proof,'POST',self.origin+'/run/renew',nonce,binding,1800);self.s.attach_trusted_run(renewed);self.now+=300
  self.assertIsNotNone(self.s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run['run_id'],idempotency_key='independent-renew'),key_bound=True))
  with self.assertRaises(Denied):self.s.attach_trusted_run({**renewed,'expires_at':renewed['expires_at']+1})
  e.revoke_connection('independent-connection',ACTOR)
  with self.assertRaises(EnrollmentDenied):self.s.attach_trusted_run(renewed)
 def test_long_role_stays_within_aws_bound(self):
  name='x'*48;s=Service(self.tmp.name+'/long.db',templates=[RoleTemplate(name,'111122223333','us-east-1',(),('ec2:DescribeInstances',))],entitlements=[Entitlement(ACTOR.owner_id,ACTOR.subject,ACTOR.client_id,(name,))],owner_id=OWNER,browser_client_id=BROWSER,offline_mode=True)
  r=s.submit(ACTOR,self.data(logical_role=name));self.assertLessEqual(len(r.manifest['physical_role_name']),64)
if __name__=='__main__':
 # Run only Fixed: its 8 inherited controls plus 9 corrected-defect probes.
 raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Fixed)).wasSuccessful())
