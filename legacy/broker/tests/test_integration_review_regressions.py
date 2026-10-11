import unittest,tempfile,json,threading,io,logging,asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from integration.fixtures import *
from integration.contracts import *
from integration.service import Conflict,Denied
from integration.http import create_app,HTTPConfig
from integration.enrollment import CoordinatorEnrollment,StandingTrust,fresh_key,make_proof
from integration.providers import AWSRuntimeCredentials

class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.now=1900000000;self.origin='http://127.0.0.1:8877'
        self.s,self.b,self.ba=make_fixture(self.tmp.name+'/s.db',clock=lambda:self.now,origin=self.origin)
    def tearDown(self):self.tmp.cleanup()
    def data(self,**kw):return RequestInput(**dict({'logical_role':'existing-ec2','expected_generation':0,'scope':{'actions':['ec2:DescribeInstances'],'instance_arns':[]},'access':'ongoing','reason':'Reviewer regression','idempotency_key':'review-request-1'},**kw))
    def approve(self,r):return self.s.decide(HUMAN,r.request_id,r.revision,r.digest,'approve')
    def active(self,**kw):
        r=self.s.submit(ACTOR,self.data(**kw));self.approve(r);self.s.execute(r.request_id);return r,self.s.grants(ACTOR).grants[-1]
    def test_stopped_temporary_never_auto_restores(self):
        self.active();r,g=self.active(expected_generation=1,access='temporary',effective_at=self.now,not_after=self.now+1800,idempotency_key='review-request-2')
        self.s.stop_grant(HUMAN,g.grant_id);self.now+=1800
        with self.assertRaises(Denied):self.s.restore(g.grant_id)
        self.assertEqual(self.s.grants(ACTOR).grants[-1].state,'stopped')
        fresh=self.s.submit(ACTOR,self.data(expected_generation=2,idempotency_key='review-request-3'))
        self.approve(fresh);self.assertEqual(self.s.execute(fresh.request_id).state,'active')
    def test_bad_receipt_operation_status_is_persisted(self):
        r=self.s.submit(ACTOR,self.data());self.approve(r);self.s.executor.apply=lambda m:{'verified':False}
        result=self.s.execute(r.request_id)
        self.assertEqual(result.state,'needs_review');self.assertEqual(self.s.operation(ACTOR,result.operation_id).state,'needs_review')
    def test_missed_start_cancel_and_fresh_revision(self):
        self.active();r=self.s.submit(ACTOR,self.data(expected_generation=1,access='temporary',effective_at=self.now,not_after=self.now+1800,idempotency_key='review-request-2'));self.approve(r);self.now+=1
        with self.assertRaises(Conflict):self.s.execute(r.request_id)
        with self.assertRaises(Conflict):self.s.cancel_pending(HUMAN,r.request_id,r.revision,'f'*64)
        with self.assertRaises(Denied):self.s.cancel_pending(ACTOR,r.request_id,r.revision,r.digest)
        self.assertEqual(self.s.cancel_pending(HUMAN,r.request_id,r.revision,r.digest).state,'cancelled')
        self.assertEqual(self.s.grants(ACTOR).grants[-1].state,'stopped')
        new=self.s.submit(ACTOR,self.data(expected_generation=1,idempotency_key='review-request-3'));self.approve(new)
        self.assertEqual(self.s.execute(new.request_id).state,'active')
    def test_cancel_cannot_release_unknown_attempt(self):
        r=self.s.submit(ACTOR,self.data());self.approve(r);self.s.executor.timeout=True
        with self.assertRaises(Denied):self.s.execute(r.request_id)
        with self.assertRaises(Conflict):self.s.cancel_pending(HUMAN,r.request_id,r.revision,r.digest)
        with self.assertRaises(Conflict):self.s.submit(ACTOR,self.data(idempotency_key='review-request-2'))
    def test_cancel_vs_execute_is_serialized(self):
        r=self.s.submit(ACTOR,self.data());self.approve(r);barrier=threading.Barrier(2)
        def cancel():
            barrier.wait()
            try:return self.s.cancel_pending(HUMAN,r.request_id,r.revision,r.digest).state
            except Conflict:return 'cancel-denied'
        def execute():
            barrier.wait()
            try:return self.s.execute(r.request_id).state
            except Conflict:return 'execute-denied'
        with ThreadPoolExecutor(2) as pool:
            a=pool.submit(cancel);b=pool.submit(execute);results=[a.result(),b.result()]
        final=self.s.request(ACTOR,r.request_id).state
        self.assertIn(final,('cancelled','active'));self.assertFalse('cancelled' in results and 'active' in results)
    def test_stop_during_restoration_provider_attempt_cannot_activate(self):
        self.active();r,g=self.active(expected_generation=1,access='temporary',effective_at=self.now,not_after=self.now+1800,idempotency_key='review-request-2');self.now+=1800
        original=self.s.executor.apply
        def stop_then_apply(m):self.s.stop_grant(HUMAN,g.grant_id);return original(m)
        self.s.executor.apply=stop_then_apply
        self.assertEqual(self.s.restore(g.grant_id).state,'needs_review');self.assertEqual(self.s.grants(ACTOR).grants[-1].state,'stopped')
    def test_mcp_schema_and_unknown_tool_values_never_echo(self):
        marker='SYNTHETIC_PRIVATE_INPUT_MUST_NOT_BE_ECHOED';log=io.StringIO();handler=logging.StreamHandler(log)
        logging.getLogger().addHandler(handler)
        try:
            with TestClient(create_app(self.s,self.b,self.ba,HTTPConfig(origin=self.origin,offline_mode=True)),base_url=self.origin) as client:
                h={'Authorization':'Bearer OFFLINE-ONLY','Accept':'application/json, text/event-stream'}
                bad=self.data().model_dump();bad['owner_id']=marker
                for name,args in [('request_permission_scope',{'request':bad}),(marker,{})]:
                    r=client.post('/mcp',headers=h,json={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args}})
                    self.assertEqual(r.status_code,200);self.assertTrue(r.json()['result']['isError']);self.assertNotIn(marker,r.text)
                self.assertNotIn(marker,log.getvalue())
        finally:logging.getLogger().removeHandler(handler)
    def test_pinned_role_map_substitution_denied_before_sts(self):
        r,g=self.active()
        with self.s.query() as db: row=dict(self.s.grant_row(db,ACTOR,g.grant_id))
        class WrongRole:
            def as_dict(self):return {'role_name':'wrong','role_arn':'arn:aws:iam::111122223333:role/wrong'}
        class STS:
            called=False
            def issue(self,*a,**kw):self.called=True
        sts=STS();provider=AWSRuntimeCredentials(sts,{g.physical_role_name:WrongRole()})
        with self.assertRaises(Denied):provider.issue(row,{'grant_id':g.grant_id,'expires':self.now+1800},self.now,self.now+900)
        self.assertFalse(sts.called)
    def test_verified_renewal_syncs_without_widening_identity(self):
        r,g=self.active();e=CoordinatorEnrollment(self.s.path,configured=True,offline_mode=True,trust=(StandingTrust(ACTOR.owner_id,ACTOR.subject,ACTOR.client_id,ACTOR.authentication_id,'review-connection'),),active_grant=self.s.coordinator_current,redeem_url=self.origin+'/enrollment/redeem',clock=lambda:self.now);self.s.run_guard=e.get_run
        key,public=fresh_key();binding=self.s.enrollment_binding(ACTOR,g.grant_id);p=e.prepare(ACTOR,public,binding,1200,'review-enrollment')
        proof=make_proof(key,public,'POST',e.redeem_url,p['challenge'],binding,enrollment_id=p['enrollment_id'],clock=lambda:self.now,offline_mode=True)
        run=e.redeem(p['enrollment_id'],proof);self.s.attach_trusted_run(run);self.now+=100
        nonce=e.issue_nonce(run['run_id']);proof=make_proof(key,public,'POST',self.origin+'/run/renew',nonce,binding,run_id=run['run_id'],clock=lambda:self.now,offline_mode=True)
        renewed=e.renew(run['run_id'],proof,'POST',self.origin+'/run/renew',nonce,binding,1800);self.s.attach_trusted_run(renewed);self.now+=300
        self.assertIsNotNone(self.s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run['run_id'],idempotency_key='review-renewal'),key_bound=True))
        forged={**renewed,'expires_at':renewed['expires_at']+1}
        with self.assertRaises(Denied):self.s.attach_trusted_run(forged)
    def test_stale_invalid_receipt_cannot_rewrite_active_state(self):
        r,g=self.active();result=self.s.finalize(r.request_id,{'verified':False})
        self.assertEqual(result.state,'active');self.assertEqual(self.s.request(ACTOR,r.request_id).state,'active');self.assertEqual(self.s.grants(ACTOR).grants[-1].state,'active')
    def test_ingress_chunked_cap_stops_consumption_early(self):
        app=create_app(self.s,self.b,self.ba,HTTPConfig(origin=self.origin,offline_mode=True,max_body_bytes=4096))
        reads=[0];messages=[]
        async def receive():
            reads[0]+=1
            return {'type':'http.request','body':b'x'*1024,'more_body':reads[0]<100}
        async def send(message):messages.append(message)
        scope={'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':'POST','scheme':'http','path':'/v1/requests','raw_path':b'/v1/requests','query_string':b'','root_path':'','headers':[(b'host',b'127.0.0.1:8877'),(b'authorization',b'Bearer OFFLINE-ONLY'),(b'transfer-encoding',b'chunked')],'client':('127.0.0.1',1234),'server':('127.0.0.1',8877)}
        asyncio.run(app(scope,receive,send))
        self.assertEqual(next(m['status'] for m in messages if m['type']=='http.response.start'),413);self.assertLessEqual(reads[0],5)
    def test_executor_receipt_binds_grant_manifest_identity_and_snapshot(self):
        from integration.providers import PinnedRevision
        from integration.aws import RoleExpectation
        from dataclasses import replace
        r,g=self.active()
        with self.s.query() as db:row=dict(self.s.grant_row(db,ACTOR,g.grant_id))
        m=json.loads(row['manifest']);policy=m['policy'];role_id='AROA1234567890EXAMPLE1'
        def expected(name=None):
            name=name or m['physical_role_name']
            return RoleExpectation(name,'arn:aws:iam::111122223333:role/'+name,role_id,{'Version':'2012-10-17','Statement':[]},{'arn':'arn:aws:iam::111122223333:policy/ceiling','version_id':'v1','document':policy},{'ApprovedRevision':policy},{})
        exp=expected();pin=PinnedRevision(g.grant_id,digest(m),role_id,exp.fingerprint,exp)
        class STS:
            calls=0
            def issue(self,*a,**kw):self.calls+=1;return 'redacted-envelope'
        sts=STS();provider=AWSRuntimeCredentials(sts,{g.physical_role_name:pin});run={'grant_id':g.grant_id,'expires':self.now+1800,'id':'run_test'}
        self.assertEqual(provider.issue(row,run,self.now,self.now+900),'redacted-envelope');self.assertEqual(sts.calls,1)
        wrong=expected('other-approved-looking-role')
        pins=[replace(pin,grant_id='other'),replace(pin,manifest_digest='a'*64),replace(pin,role_id='AROAOTHER1234567890'),replace(pin,snapshot_sha256='b'*64),replace(pin,expectation=wrong,snapshot_sha256=wrong.fingerprint)]
        for bad in pins:
            with self.assertRaises(Denied):AWSRuntimeCredentials(sts,{g.physical_role_name:bad}).issue(row,run,self.now,self.now+900)
        self.assertEqual(sts.calls,1)
    def test_browser_cancel_uses_exact_challenge_and_no_bearer(self):
        r=self.s.submit(ACTOR,self.data());self.approve(r)
        with TestClient(create_app(self.s,self.b,self.ba,HTTPConfig(origin=self.origin,offline_mode=True)),base_url=self.origin) as client:
            import re
            client.get('/offline/login');response=client.get('/browser/requests/'+r.request_id)
            form=dict(re.findall(r'name="([^"]+)" value="([^"]+)"',response.text));form['choice']='cancel'
            bad=client.post('/browser/requests/'+r.request_id+'/decision',data=form,headers={'Origin':self.origin,'Authorization':'Bearer OFFLINE-ONLY'})
            self.assertEqual(bad.status_code,403)
            ok=client.post('/browser/requests/'+r.request_id+'/decision',data=form,headers={'Origin':self.origin},follow_redirects=False)
            self.assertEqual(ok.status_code,303);self.assertEqual(self.s.request(ACTOR,r.request_id).state,'cancelled')
    def test_long_logical_name_generates_valid_physical_name(self):
        from integration.service import RoleTemplate,Entitlement,Service
        name='x'*48
        s=Service(self.tmp.name+'/long.db',templates=[RoleTemplate(name,'111122223333','us-east-1',(),('ec2:DescribeInstances',))],entitlements=[Entitlement(ACTOR.owner_id,ACTOR.subject,ACTOR.client_id,(name,))],owner_id=HUMAN.owner_id,browser_client_id=HUMAN.client_id,offline_mode=True)
        request=s.submit(ACTOR,self.data(logical_role=name))
        self.assertLessEqual(len(request.manifest['physical_role_name']),64)
    def test_malformed_mcp_envelope_is_redacted(self):
        marker='SYNTHETIC_PRIVATE_INPUT_MUST_NOT_BE_ECHOED'
        with TestClient(create_app(self.s,self.b,self.ba,HTTPConfig(origin=self.origin,offline_mode=True)),base_url=self.origin) as client:
            h={'Authorization':'Bearer OFFLINE-ONLY','Accept':'application/json, text/event-stream'}
            messages=[{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':[marker]}},{'jsonrpc':'2.0','id':1,'method':marker,'params':{}},{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'clientInfo':marker}},{'jsonrpc':'2.0','id':1,'method':'logging/setLevel','params':{'level':'debug'}},{'jsonrpc':'2.0','id':1,'method':'resources/read','params':{'uri':'https://example.invalid/'+marker}},{'jsonrpc':'2.0','id':1,'method':'prompts/get','params':{'name':marker}}]
            for message in messages:
                response=client.post('/mcp',headers=h,json=message)
                self.assertEqual(response.status_code,400);self.assertNotIn(marker,response.text)
    def test_aws_temporary_admission_900_959_960_boundaries(self):
        for seconds in (900,959):
            with self.assertRaises(Denied):self.s.submit(ACTOR,self.data(access='temporary',effective_at=self.now,not_after=self.now+seconds,idempotency_key='boundary-'+str(seconds)))
        r,g=self.active(access='temporary',effective_at=self.now,not_after=self.now+960)
        run=self.s.enroll(ACTOR,RunEnrollmentInput(grant_id=g.grant_id,evidence='OFFLINE-ONLY'))
        self.assertIsNotNone(self.s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run.run_id,idempotency_key='boundary-960')))
    def test_aws_enrollment_input_900_959_960_boundaries(self):
        from pydantic import ValidationError
        for seconds in (900,959):
            with self.assertRaises(ValidationError):EnrollmentPrepareInput(grant_id='g',public_jwk={},lifetime=seconds,idempotency_key='boundary-input')
        self.assertEqual(EnrollmentPrepareInput(grant_id='g',public_jwk={},lifetime=960,idempotency_key='boundary-input').lifetime,960)
