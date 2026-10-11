"""Independent offline transport/control probes. No provider network clients."""
import concurrent.futures, dataclasses, json, re, sqlite3, tempfile, threading, unittest
from fastapi.testclient import TestClient
from integration.fixtures import ACTOR,HUMAN,make_fixture
from integration.contracts import RequestInput,LeaseInput,RunEnrollmentInput,digest
from integration.http import create_app,HTTPConfig
from integration.enrollment import CoordinatorEnrollment,StandingTrust,fresh_key,make_proof
from integration.service import Denied,Conflict

class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.now=1900000000;self.origin='http://127.0.0.1:8877'
  self.s,self.b,self.ba=make_fixture(self.tmp.name+'/state.db',clock=lambda:self.now,origin=self.origin)
 def tearDown(self):self.tmp.cleanup()
 def data(self,**kw):
  d={'logical_role':'existing-ec2','expected_generation':0,'scope':{'actions':['ec2:DescribeInstances'],'instance_arns':[]},'access':'ongoing','reason':'Synthetic independent review','idempotency_key':'independent-0001'};d.update(kw);return RequestInput(**d)
 def active(self):
  r=self.s.submit(ACTOR,self.data());self.s.decide(HUMAN,r.request_id,r.revision,r.digest,'approve');self.s.execute(r.request_id);return r,self.s.grants(ACTOR).grants[0]
 def dump(self):
  with sqlite3.connect(self.s.path) as db:return '\n'.join(db.iterdump())
 def client(self):return TestClient(create_app(self.s,self.b,self.ba,HTTPConfig(origin=self.origin,offline_mode=True,requests_per_minute=1000)),base_url=self.origin)
 def test_concurrent_request_idempotency_one_row(self):
  barrier=threading.Barrier(12)
  def submit(i):barrier.wait();return self.s.submit(ACTOR,self.data()).request_id
  with concurrent.futures.ThreadPoolExecutor(max_workers=12) as p:ids=list(p.map(submit,range(12)))
  self.assertEqual(len(set(ids)),1)
  with sqlite3.connect(self.s.path) as db:self.assertEqual(db.execute('select count(*) from requests').fetchone()[0],1)
 def test_concurrent_browser_decision_single_effect(self):
  r=self.s.submit(ACTOR,self.data());barrier=threading.Barrier(12)
  def approve(i):
   barrier.wait()
   try:self.s.decide(HUMAN,r.request_id,r.revision,r.digest,'approve');return True
   except Conflict:return False
  with concurrent.futures.ThreadPoolExecutor(max_workers=12) as p:self.assertEqual(sum(p.map(approve,range(12))),1)
  with sqlite3.connect(self.s.path) as db:self.assertEqual(db.execute('select count(*) from decisions').fetchone()[0],1)
 def test_cross_actor_request_grant_and_lease_denied(self):
  r,g=self.active();run=self.s.enroll(ACTOR,RunEnrollmentInput(grant_id=g.grant_id,evidence='OFFLINE-ONLY'))
  for p in [dataclasses.replace(ACTOR,owner_id='other'),dataclasses.replace(ACTOR,subject='other'),dataclasses.replace(ACTOR,client_id='other')]:
   with self.assertRaises(Denied):self.s.request(p,r.request_id)
   with self.assertRaises(Denied):self.s.lease(p,LeaseInput(grant_id=g.grant_id,run_id=run.run_id,idempotency_key='independent-lease'))
 def test_pure_reads_after_unknown_outcome_do_not_reconcile(self):
  r=self.s.submit(ACTOR,self.data());self.s.decide(HUMAN,r.request_id,r.revision,r.digest,'approve');self.s.executor.timeout=True
  with self.assertRaises(Denied):self.s.execute(r.request_id)
  before=self.dump();writes=self.s.executor.writes
  for _ in range(10):
   self.s.request(ACTOR,r.request_id);self.s.requests(ACTOR);self.s.grants(ACTOR);self.s.operation(ACTOR,self.s.request(ACTOR,r.request_id).operation_id)
  self.assertEqual(before,self.dump());self.assertEqual(writes,self.s.executor.writes)
 def test_stale_browser_form_and_same_owner_bearer_cannot_approve(self):
  r=self.s.submit(ACTOR,self.data())
  with self.client() as c:
   c.get('/offline/login');review=c.get('/browser/requests/'+r.request_id);form=dict(re.findall(r'name="([^"]+)" value="([^"]+)"',review.text));form['choice']='approve'
   self.s.submit(ACTOR,self.data(reason='Changed scope rationale',idempotency_key='independent-0002'),r.request_id,1)
   path='/browser/requests/'+r.request_id+'/decision'
   self.assertEqual(c.post(path,data=form,headers={'Origin':self.origin},follow_redirects=False).status_code,409)
   fresh=c.get('/browser/requests/'+r.request_id);form=dict(re.findall(r'name="([^"]+)" value="([^"]+)"',fresh.text));form['choice']='approve'
   self.assertEqual(c.post(path,data=form,headers={'Origin':self.origin,'Authorization':'Bearer OFFLINE-ONLY'},follow_redirects=False).status_code,403)
   self.assertEqual(self.s.request(ACTOR,r.request_id).state,'awaiting_owner')
 def test_mcp_reads_pure_no_credential_tools(self):
  self.active()
  with self.client() as c:
   headers={'Authorization':'Bearer OFFLINE-ONLY','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-06-18'}
   def rpc(method,params):return c.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':method,'params':params}).json()
   tools=rpc('tools/list',{})['result']['tools']
   self.assertFalse(any(any(w in x['name'] for w in ['redeem','approve','execute','credential_process']) for x in tools))
   self.assertFalse(next(x for x in tools if x['name']=='prepare_run_enrollment')['annotations']['readOnlyHint'])
   before=self.dump()
   for name in ['list_permission_requests','list_permission_grants']:
    result=rpc('tools/call',{'name':name,'arguments':{}});raw=json.dumps(result)
    for word in ['SecretAccessKey','SessionToken','OFFLINE_NOT_A_REAL']:self.assertNotIn(word,raw)
   self.assertEqual(before,self.dump())
 def test_credential_handle_parallel_redemption_exactly_one(self):
  _,g=self.active();run=self.s.enroll(ACTOR,RunEnrollmentInput(grant_id=g.grant_id,evidence='OFFLINE-ONLY'));lease=self.s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run.run_id,idempotency_key='independent-lease'))
  barrier=threading.Barrier(12)
  def redeem(i):
   barrier.wait()
   try:self.s.redeem(ACTOR,lease.handle);return True
   except Denied:return False
  with concurrent.futures.ThreadPoolExecutor(max_workers=12) as p:self.assertEqual(sum(p.map(redeem,range(12))),1)
 def test_stopped_grant_blocks_existing_prepared_handle(self):
  _,g=self.active();run=self.s.enroll(ACTOR,RunEnrollmentInput(grant_id=g.grant_id,evidence='OFFLINE-ONLY'));lease=self.s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run.run_id,idempotency_key='independent-lease'))
  self.s.stop_grant(HUMAN,g.grant_id)
  with self.assertRaises(Denied):self.s.redeem(ACTOR,lease.handle)
if __name__=='__main__':unittest.main(verbosity=2)
