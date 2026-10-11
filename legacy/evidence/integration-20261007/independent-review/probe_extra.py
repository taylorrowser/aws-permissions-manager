import tempfile,json
from integration.fixtures import make_fixture,ACTOR,HUMAN
from integration.contracts import RequestInput
from integration.service import RoleTemplate,Entitlement,Service,Conflict
from integration.providers import AWSRuntimeCredentials
from integration.aws import RoleExpectation,REVISION_POLICY_NAME
now=1900000000
base={'logical_role':'existing-ec2','expected_generation':0,'scope':{'actions':['ec2:DescribeInstances'],'instance_arns':[]},'access':'ongoing','reason':'Independent synthetic review','idempotency_key':'independent-0001'}
results={}
with tempfile.TemporaryDirectory() as t:
 s,*_=make_fixture(t+'/db',clock=lambda:now)
 d=RequestInput(**{**base,'access':'temporary','effective_at':now+10,'not_after':now+1810})
 r=s.submit(ACTOR,d);s.decide(HUMAN,r.request_id,r.revision,r.digest,'approve');now+=11
 for name,call in [('execute',lambda:s.execute(r.request_id)),('new_request',lambda:s.submit(ACTOR,RequestInput(**{**base,'idempotency_key':'independent-0002'}))),('revise',lambda:s.submit(ACTOR,RequestInput(**{**base,'idempotency_key':'independent-0003'}),r.request_id,1))]:
  try:call();results[name]='allowed'
  except Conflict as exc:results[name]=str(exc)
with tempfile.TemporaryDirectory() as t:
 s,*_=make_fixture(t+'/db',clock=lambda:now)
 r=s.submit(ACTOR,RequestInput(**base));s.decide(HUMAN,r.request_id,r.revision,r.digest,'approve');s.execute(r.request_id)
 with s.query() as db:g=dict(db.execute('select * from grants').fetchone())
 m=json.loads(g['manifest']);other='broker-unapproved-other-role';other_arn='arn:aws:iam::111122223333:role/'+other
 e=RoleExpectation(other,other_arn,'AROA1234567890EXAMPLE1',{'Statement':[]},{'arn':'arn:aws:iam::111122223333:policy/boundary','version_id':'v1','document':m['policy']},{REVISION_POLICY_NAME:m['policy']},{})
 class StubSTS:
  def issue(self,expected,*args,**kwargs):return {'issued_for_arn':expected.as_dict()['role_arn']}
 result=AWSRuntimeCredentials(StubSTS(),{g['physical_name']:e}).issue(g,{'grant_id':g['id'],'expires':now+2000,'id':'run_test'},now,now+900)
 results['pinned_mapping_arn_binding']={'approved_arn':m['physical_role_arn'],**result}
print(json.dumps(results,indent=2))
