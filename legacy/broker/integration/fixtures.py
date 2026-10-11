"""Conspicuous OFFLINE fixtures. Imported only by explicit demo/test setup."""
from datetime import datetime,timezone
import time
from .auth import Principal,AuthError,BrowserAuth,BrowserConfig,BearerVerifier,WorkOSConfig
from .service import Service,RoleTemplate,Entitlement,Denied
from .contracts import digest
from .aws import CredentialEnvelope
OWNER='fixture-owner'; CLIENT='fixture-cli'; BROWSER='fixture-browser'
ARN='arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0'
ACTOR=Principal(OWNER,OWNER,CLIENT,'bearer_user',None,'fixture-cli-session')
HUMAN=Principal(OWNER,OWNER,BROWSER,'human_browser',None,'fixture-human-session')

class FixtureBearer:
    offline_only=True
    def verify_authorization(self,header):
        if header!='Bearer OFFLINE-ONLY': raise AuthError('offline fixture token required')
        return ACTOR
class FixtureExecutor:
    def __init__(self): self.applied={}; self.writes=0; self.timeout=False
    def apply(self,m):
        old=self.applied.get(m['physical_role_name'])
        if old and old!=digest(m): raise Denied('unknown physical revision')
        self.applied[m['physical_role_name']]=digest(m); self.writes+=not bool(old)
        if self.timeout: raise RuntimeError('synthetic lost acknowledgement')
        return self.observe(m)
    def observe(self,m):
        return {'manifest_digest':self.applied.get(m['physical_role_name']),'physical_role_name':m['physical_role_name'],'verified':self.applied.get(m['physical_role_name'])==digest(m)}
class FixtureEnrollment:
    name='OFFLINE-FIXTURE-NOT-ATTESTATION'
    def verify(self,evidence,p,grant,now):
        if evidence!='OFFLINE-ONLY': raise Denied('offline fixture evidence required')
        return {'grant_id':grant['id'],'subject':p.subject,'client_id':p.client_id,'expires_at':now+3600}
class FixtureCredentials:
    def issue(self,grant,run,now,expires_at):
        return CredentialEnvelope({'AccessKeyId':'OFFLINE_NOT_A_REAL_ACCESS_KEY','SecretAccessKey':'OFFLINE_NOT_A_REAL_SECRET','SessionToken':'OFFLINE_NOT_A_REAL_TOKEN','Expiration':datetime.fromtimestamp(expires_at,timezone.utc)},role_arn='arn:aws:iam::111122223333:role/'+grant['physical_name'],cutoff=expires_at,snapshot_sha256=digest(grant['manifest']))

def make_fixture(path,clock=time.time,origin='http://127.0.0.1:8877'):
    t=RoleTemplate('existing-ec2','111122223333','us-east-1',(ARN,),('ec2:DescribeInstances','ec2:DescribeInstanceStatus','ec2:StartInstances','ec2:StopInstances','ec2:RebootInstances'))
    executor=FixtureExecutor()
    service=Service(path,templates=[t],entitlements=[Entitlement(OWNER,OWNER,CLIENT,('existing-ec2',))],owner_id=OWNER,browser_client_id=BROWSER,executor=executor,enrollment=FixtureEnrollment(),credentials=FixtureCredentials(),clock=clock,offline_mode=True)
    from cryptography.hazmat.primitives.asymmetric import rsa
    import jwt,json
    public=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key())); public['kid']='offline-test-key'
    verifier=BearerVerifier(WorkOSConfig(issuer='https://fixture.invalid',audience=None,owner_id=OWNER,owner_subject=OWNER,allowed_client_ids=frozenset([BROWSER]),organization_mode='none',token_profile='session'),jwks={'keys':[public]},clock=clock)
    browser=BrowserAuth(BrowserConfig(client_id=BROWSER,origin=origin,redirect_uri=origin+'/auth/callback',authorization_endpoint='https://fixture.invalid/authorize',production=False),verifier,offline_mode=True,clock=clock)
    return service,FixtureBearer(),browser
