import unittest,tempfile,json
from fastapi.testclient import TestClient
from integration.fixtures import *
from integration.contracts import *
from integration.http import create_app,HTTPConfig
from integration.enrollment import CoordinatorEnrollment,StandingTrust,fresh_key,make_proof

class CoordinatorHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.origin='http://127.0.0.1:8877'
        self.s,b,browser=make_fixture(self.tmp.name+'/s.db',origin=self.origin)
        self.e=CoordinatorEnrollment(self.s.path,configured=True,offline_mode=True,trust=(StandingTrust(ACTOR.owner_id,ACTOR.subject,ACTOR.client_id,ACTOR.authentication_id,'fixture-connection'),),active_grant=self.s.coordinator_current,redeem_url=self.origin+'/enrollment/redeem')
        self.client=TestClient(create_app(self.s,b,browser,HTTPConfig(origin=self.origin,offline_mode=True),coordinator=self.e),base_url=self.origin);self.client.__enter__()
        data=RequestInput(logical_role='existing-ec2',expected_generation=0,scope=Scope(actions=['ec2:DescribeInstances']),access='ongoing',reason='Inspect only',idempotency_key='request-0001')
        r=self.s.submit(ACTOR,data);self.s.decide(HUMAN,r.request_id,r.revision,r.digest,'approve');self.s.execute(r.request_id)
        self.g=self.s.grants(ACTOR).grants[0];self.private,self.public=fresh_key();self.headers={'Authorization':'Bearer OFFLINE-ONLY'}
    def tearDown(self):self.client.__exit__(None,None,None);self.tmp.cleanup()
    def enroll(self):
        data={'grant_id':self.g.grant_id,'public_jwk':self.public,'lifetime':1800,'idempotency_key':'enroll-0001'}
        prepared=self.client.post('/v1/enrollments',json=data,headers=self.headers)
        self.assertEqual(prepared.status_code,200,prepared.text);p=prepared.json()
        self.assertNotIn('SecretAccessKey',prepared.text);self.assertNotIn('private',prepared.text.lower())
        self.binding=p['authority']['grant_binding'];body={'enrollment_id':p['enrollment_id']}
        proof=make_proof(self.private,self.public,'POST',self.origin+'/enrollment/redeem',p['challenge'],self.binding,enrollment_id=p['enrollment_id'],body_digest=digest(body),offline_mode=True)
        r=self.client.post('/enrollment/redeem',json=body,headers={'DPoP':proof})
        self.assertEqual(r.status_code,200,r.text);self.assertEqual(self.client.post('/enrollment/redeem',json=body,headers={'DPoP':proof}).status_code,401)
        return r.json()
    def credential_body(self,run):return {'run_id':run['run_id'],'grant_id':self.g.grant_id,'nonce':run['nonce'],'idempotency_key':'credential-0001'}
    def proof(self,run,body):return make_proof(self.private,self.public,'POST',self.origin+'/run/credential-process',run['nonce'],self.binding,run_id=run['run_id'],body_digest=digest(body),offline_mode=True)
    def test_private_consumer_path_and_replay(self):
        run=self.enroll();body=self.credential_body(run);proof=self.proof(run,body)
        private=self.client.post('/run/credential-process',json=body,headers={'DPoP':proof})
        self.assertEqual(private.status_code,200,private.text);self.assertEqual(private.json()['Version'],1)
        self.assertEqual(self.client.post('/run/credential-process',json=body,headers={'DPoP':proof}).status_code,401)
        self.assertNotIn('SecretAccessKey',self.client.get('/v1/grants',headers=self.headers).text)
    def test_coordinator_bearer_cannot_bypass_key(self):
        run=self.enroll();body={'grant_id':self.g.grant_id,'run_id':run['run_id'],'idempotency_key':'lease-bypass'}
        r=self.client.post('/v1/leases',headers=self.headers,json=body);self.assertEqual(r.status_code,403,r.text)
    def test_run_revocation_rechecked_at_issuance(self):
        run=self.enroll();body=self.credential_body(run);proof=self.proof(run,body)
        self.e.revoke_run(run['run_id'],ACTOR)
        self.assertEqual(self.client.post('/run/credential-process',json=body,headers={'DPoP':proof}).status_code,401)
    def test_body_tampering_fails(self):
        run=self.enroll();body=self.credential_body(run);proof=self.proof(run,body);body['idempotency_key']='credential-changed'
        self.assertEqual(self.client.post('/run/credential-process',json=body,headers={'DPoP':proof}).status_code,401)
