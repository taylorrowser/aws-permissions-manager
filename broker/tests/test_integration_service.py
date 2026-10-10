import unittest,tempfile,os,json,sqlite3
from dataclasses import replace
from integration.fixtures import *
from integration.service import *
from integration.contracts import *

class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.now=1900000000
        self.s,_,self.browser=make_fixture(self.tmp.name+'/s.db',clock=lambda:self.now)
    def tearDown(self): self.tmp.cleanup()
    def data(self,**kw):
        return RequestInput(**dict({'logical_role':'existing-ec2','expected_generation':0,'scope':{'actions':['ec2:DescribeInstances'],'instance_arns':[]},'access':'ongoing','reason':'Inspect existing instance status','idempotency_key':'request-0001'},**kw))
    def approve(self,r): return self.s.decide(HUMAN,r.request_id,r.revision,r.digest,'approve')
    def active(self,**kw):
        r=self.s.submit(ACTOR,self.data(**kw)); self.approve(r); self.s.execute(r.request_id)
        return r,self.s.grants(ACTOR).grants[-1]
    def snapshot(self):
        with sqlite3.connect(self.s.path) as db: return '\n'.join(db.iterdump())
    def test_request_revision_and_old_digest(self):
        r=self.s.submit(ACTOR,self.data()); r2=self.s.submit(ACTOR,self.data(reason='New reason',idempotency_key='request-0002'),r.request_id,1)
        with self.assertRaises(Conflict): self.s.decide(HUMAN,r.request_id,1,r.digest,'approve')
        self.assertEqual(r2.revision,2); self.approve(r2)
    def test_agent_same_owner_cannot_approve(self):
        r=self.s.submit(ACTOR,self.data())
        with self.assertRaises(Denied): self.s.decide(ACTOR,r.request_id,1,r.digest,'approve')
    def test_missing_entitlement_and_cross_user(self):
        r=self.s.submit(ACTOR,self.data())
        for p in [replace(ACTOR,subject='other'),replace(ACTOR,client_id='other'),replace(ACTOR,owner_id='other')]:
            with self.assertRaises(Denied): self.s.request(p,r.request_id)
            with self.assertRaises(Denied): self.s.submit(p,self.data())
    def test_idempotent_request_no_write(self):
        r=self.s.submit(ACTOR,self.data()); snap=self.snapshot()
        self.assertEqual(r,self.s.submit(ACTOR,self.data())); self.assertEqual(snap,self.snapshot())
        with self.assertRaises(Conflict): self.s.submit(ACTOR,self.data(reason='different'))
    def test_reads_are_pure_even_expired(self):
        r,g=self.active(access='temporary',effective_at=self.now,not_after=self.now+1800)
        self.now+=2000; snap=self.snapshot()
        self.s.request(ACTOR,r.request_id); self.s.requests(ACTOR); self.s.grants(ACTOR); self.s.operation(ACTOR,g.operation_id)
        self.assertEqual(snap,self.snapshot()); self.assertEqual(self.s.grants(ACTOR).grants[0].state,'expired')
    def test_unconfigured_denies(self):
        s=Service(self.tmp.name+'/unconfigured.db')
        with self.assertRaises(Unconfigured): s.execute('anything')
        with self.assertRaises(Unconfigured): s.enroll(ACTOR,RunEnrollmentInput(grant_id='g',evidence='label'))
    def test_role_lease_drain_and_new_physical_revision(self):
        r,g=self.active(); run=self.s.enroll(ACTOR,RunEnrollmentInput(grant_id=g.grant_id,evidence='OFFLINE-ONLY'))
        lease=self.s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run.run_id,idempotency_key='lease-0001'))
        self.s.redeem(ACTOR,lease.handle)
        newer=self.s.submit(ACTOR,self.data(expected_generation=1,scope={'actions':['ec2:DescribeInstanceStatus'],'instance_arns':[]},idempotency_key='request-0002'))
        self.approve(newer)
        with self.assertRaises(Denied): self.s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run.run_id,idempotency_key='lease-0002'))
        self.assertEqual(self.s.execute(newer.request_id).state,'draining')
        self.now=lease.maximum_expiration
        self.assertEqual(self.s.execute(newer.request_id).state,'active')
        gs=self.s.grants(ACTOR).grants; self.assertNotEqual(gs[0].physical_role_name,gs[1].physical_role_name)
        self.assertEqual(gs[0].state,'superseded')
    def test_unknown_outcome_reserves_until_reconciliation(self):
        r=self.s.submit(ACTOR,self.data()); self.approve(r); self.s.executor.timeout=True
        with self.assertRaises(Denied): self.s.execute(r.request_id)
        with self.assertRaises(Conflict): self.s.submit(ACTOR,self.data(idempotency_key='request-0002'))
        writes=self.s.executor.writes; self.assertEqual(self.s.reconcile(r.request_id).state,'active'); self.assertEqual(writes,self.s.executor.writes)
    def test_lease_replay_and_minimum(self):
        r,g=self.active(); run=self.s.enroll(ACTOR,RunEnrollmentInput(grant_id=g.grant_id,evidence='OFFLINE-ONLY'))
        data=LeaseInput(grant_id=g.grant_id,run_id=run.run_id,idempotency_key='lease-0001'); lease=self.s.lease(ACTOR,data)
        self.assertEqual(lease,self.s.lease(ACTOR,data)); envelope=self.s.redeem(ACTOR,lease.handle)
        self.assertNotIn('OFFLINE_NOT_A_REAL_SECRET',repr(envelope))
        with self.assertRaises(Denied): self.s.redeem(ACTOR,lease.handle)
        self.now+=2700
        with self.assertRaises(Denied): self.s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run.run_id,idempotency_key='lease-0002'))
    def test_unsupported_scopes_and_ceilings(self):
        from pydantic import ValidationError
        with self.assertRaises(ValidationError): self.data(scope={'actions':['ec2:TerminateInstances'],'instance_arns':[ARN]})
        with self.assertRaises(Denied): self.s.submit(ACTOR,self.data(scope={'actions':['ec2:StartInstances'],'instance_arns':[ARN.replace('111122223333','444455556666')]}))
    def test_start_window_cannot_be_silently_shortened(self):
        r,g=self.active(); run=self.s.enroll(ACTOR,RunEnrollmentInput(grant_id=g.grant_id,evidence='OFFLINE-ONLY'))
        self.s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run.run_id,idempotency_key='lease-0001'))
        r2=self.s.submit(ACTOR,self.data(expected_generation=1,access='temporary',effective_at=self.now+1,not_after=self.now+1800,idempotency_key='request-0002'))
        with self.assertRaises(Conflict): self.approve(r2)
    def test_duplicate_approval_and_stale_generation(self):
        r,g=self.active()
        with self.assertRaises(Conflict): self.approve(r)
        with self.assertRaises(Conflict): self.s.submit(ACTOR,self.data(idempotency_key='request-0002'))

if __name__=='__main__': unittest.main()

class TransitionTests(unittest.TestCase):
    setUp=ServiceTests.setUp
    tearDown=ServiceTests.tearDown
    data=ServiceTests.data
    approve=ServiceTests.approve
    active=ServiceTests.active
    def test_temporary_reduction_restores_new_revision(self):
        r,g=self.active(scope={'actions':['ec2:DescribeInstances','ec2:StopInstances'],'instance_arns':[ARN]})
        reduced=self.s.submit(ACTOR,self.data(expected_generation=1,access='temporary',effective_at=self.now,not_after=self.now+1800,idempotency_key='request-0002'))
        self.assertIsNotNone(reduced.manifest['restoration']); self.assertIn('physical_role_arn',reduced.manifest['restoration'])
        self.approve(reduced);self.s.execute(reduced.request_id);temp=self.s.grants(ACTOR).grants[-1]
        with self.assertRaises(Conflict): self.s.restore(temp.grant_id)
        self.now+=1800;self.assertEqual(self.s.restore(temp.grant_id).state,'active')
        grants=self.s.grants(ACTOR).grants;self.assertEqual(len(grants),3)
        self.assertEqual(grants[-1].scope,grants[0].scope);self.assertEqual(len({g.physical_role_name for g in grants}),3)
        self.assertEqual(grants[0].state,'superseded');self.assertEqual(grants[1].state,'superseded')
    def test_stop_does_not_claim_aws_revoke(self):
        r,g=self.active();self.s.stop_grant(HUMAN,g.grant_id)
        self.assertEqual(self.s.grants(ACTOR).grants[0].state,'stopped')
        with self.assertRaises(Denied): self.s.enroll(ACTOR,RunEnrollmentInput(grant_id=g.grant_id,evidence='OFFLINE-ONLY'))
