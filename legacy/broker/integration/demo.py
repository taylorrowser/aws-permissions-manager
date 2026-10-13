"""Non-live acceptance walkthrough. Emits sanitized results, never credential bodies."""
import tempfile,json,io
from .fixtures import make_fixture,ACTOR,HUMAN,ARN
from .contracts import RequestInput,Scope,RunEnrollmentInput,LeaseInput

def run():
    with tempfile.TemporaryDirectory() as d:
        service,_,_=make_fixture(d+'/offline.db')
        request=service.submit(ACTOR,RequestInput(logical_role='existing-ec2',expected_generation=0,scope=Scope(actions=['ec2:DescribeInstances','ec2:StopInstances'],instance_arns=[ARN]),access='ongoing',reason='Inspect and stop this explicitly approved existing instance',idempotency_key='demo-request-1'))
        service.decide(HUMAN,request.request_id,request.revision,request.digest,'approve')
        operation=service.execute(request.request_id); grant=service.grants(ACTOR).grants[0]
        run=service.enroll(ACTOR,RunEnrollmentInput(grant_id=grant.grant_id,evidence='OFFLINE-ONLY'))
        lease=service.lease(ACTOR,LeaseInput(grant_id=grant.grant_id,run_id=run.run_id,idempotency_key='demo-lease-1'))
        envelope=service.redeem(ACTOR,lease.handle)
        # Models an SDK consumer's private pipe. No raw body is returned to the caller.
        private=io.StringIO(); envelope.write_credential_process(private)
        consumer=json.loads(private.getvalue()); valid=consumer['Version']==1 and bool(consumer['AccessKeyId'])
        return {'mode':'OFFLINE FIXTURE ONLY','request_state':service.request(ACTOR,request.request_id).state,
                'operation_state':operation.state,'scope_actions':grant.scope.actions,'new_physical_revision':True,
                'private_consumer_authenticated':valid,'credential_body_reported':False,'live_provider_calls':0,
                'browser_rendering':'unverified; documented environment restrictions'}
if __name__=='__main__': print(json.dumps(run(),indent=2))
