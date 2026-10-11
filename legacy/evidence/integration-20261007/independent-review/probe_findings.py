import tempfile, json, re, sqlite3, sys
from fastapi.testclient import TestClient
from integration.fixtures import make_fixture, ACTOR, HUMAN, ARN
from integration.contracts import RequestInput, Scope, digest, LeaseInput
from integration.http import create_app, HTTPConfig
from integration.enrollment import CoordinatorEnrollment,StandingTrust,fresh_key,make_proof
from integration.service import Denied, Conflict

results={}; now=[1900000000]; origin='http://127.0.0.1:8877'
def data(**kw):
 d={'logical_role':'existing-ec2','expected_generation':0,'scope':{'actions':['ec2:DescribeInstances'],'instance_arns':[]},'access':'ongoing','reason':'Independent synthetic review','idempotency_key':'independent-0001'};d.update(kw);return RequestInput(**d)
def activate(s,**kw):
 r=s.submit(ACTOR,data(**kw));s.decide(HUMAN,r.request_id,r.revision,r.digest,'approve');s.execute(r.request_id);return r,s.grants(ACTOR).grants[-1]
with tempfile.TemporaryDirectory() as t:
 s,b,ba=make_fixture(t+'/state.db',origin=origin,clock=lambda:now[0])
 r,g=activate(s,scope={'actions':['ec2:DescribeInstances','ec2:StopInstances'],'instance_arns':[ARN]})
 r2,g2=activate(s,expected_generation=1,access='temporary',effective_at=now[0],not_after=now[0]+1800,idempotency_key='independent-0002')
 s.stop_grant(HUMAN,g2.grant_id); now[0]+=1800; result=s.restore(g2.grant_id)
 results['stop_temporary_then_restore']={'operation_state':result.state,'grant_states':[g.state for g in s.grants(ACTOR).grants]}
with tempfile.TemporaryDirectory() as t:
 s,b,ba=make_fixture(t+'/state.db',origin=origin,clock=lambda:now[0])
 r=s.submit(ACTOR,data());s.decide(HUMAN,r.request_id,r.revision,r.digest,'approve')
 s.executor.apply=lambda m:{'verified':False}
 result=s.execute(r.request_id)
 results['invalid_receipt_operation']={'returned':result.state,'request':s.request(ACTOR,r.request_id).state,'operation':s.operation(ACTOR,result.operation_id).state}
with tempfile.TemporaryDirectory() as t:
 s,b,ba=make_fixture(t+'/state.db',origin=origin,clock=lambda:now[0])
 with TestClient(create_app(s,b,ba,HTTPConfig(origin=origin,offline_mode=True)),base_url=origin) as c:
  headers={'Authorization':'Bearer OFFLINE-ONLY','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-06-18'}
  marker='SYNTHETIC_PRIVATE_INPUT_MUST_NOT_BE_ECHOED'
  bad=data().model_dump();bad['owner_id']=marker
  r=c.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'request_permission_scope','arguments':{'request':bad}}})
  results['mcp_validation_redaction']={'http':r.status_code,'echoes_synthetic_secret_marker':marker in r.text,'isError':r.json().get('result',{}).get('isError')}
with tempfile.TemporaryDirectory() as t:
 s,b,ba=make_fixture(t+'/state.db',origin=origin,clock=lambda:now[0]);r,g=activate(s)
 e=CoordinatorEnrollment(s.path,configured=True,offline_mode=True,trust=(StandingTrust(ACTOR.owner_id,ACTOR.subject,ACTOR.client_id,ACTOR.authentication_id,'independent-connection'),),active_grant=s.coordinator_current,redeem_url=origin+'/enrollment/redeem',clock=lambda:now[0]);s.run_guard=e.get_run
 key,public=fresh_key(); binding=s.enrollment_binding(ACTOR,g.grant_id)
 p=e.prepare(ACTOR,public,binding,1200,'independent-enrollment')
 run=e.redeem(p['enrollment_id'],make_proof(key,public,'POST',e.redeem_url,p['challenge'],binding,enrollment_id=p['enrollment_id'],clock=lambda:now[0],offline_mode=True));s.attach_trusted_run(run)
 for _ in range(20):e.issue_nonce(run['run_id'])
 proof=make_proof(key,public,'POST',origin+'/run/credential-process',run['nonce'],binding,run_id=run['run_id'],clock=lambda:now[0],offline_mode=True)
 valid=e.validate_request(run['run_id'],proof,'POST',origin+'/run/credential-process',run['nonce'],binding)
 results['public_nonce_no_invalidation']={'original_nonce_still_works':valid['run_id']==run['run_id']}
 try:s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run['run_id'],idempotency_key='independent-bypass'))
 except Denied:results['generic_bearer_cannot_lease_key_run']=True
 else:results['generic_bearer_cannot_lease_key_run']=False
 now[0]+=100;nonce=e.issue_nonce(run['run_id']);proof=make_proof(key,public,'POST',origin+'/run/renew',nonce,binding,run_id=run['run_id'],clock=lambda:now[0],offline_mode=True)
 renewed=e.renew(run['run_id'],proof,'POST',origin+'/run/renew',nonce,binding,1800);s.attach_trusted_run(renewed)
 now[0]+=300
 try:s.lease(ACTOR,LeaseInput(grant_id=g.grant_id,run_id=run['run_id'],idempotency_key='independent-renewed'),key_bound=True)
 except Denied as exc:results['renewed_run_usable']={'renewal_expiry':renewed['expires_at'],'current_time':now[0],'result':str(exc),'enrollment_authority_active':e.get_run(run['run_id'])['state']}
 else:results['renewed_run_usable']={'result':'lease accepted'}
print(json.dumps(results,indent=2))
