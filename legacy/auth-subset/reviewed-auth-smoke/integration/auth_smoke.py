"""Separately reviewed, memory-only public-auth smoke harness.

NO live invocation is authorized by this source. The parent must first approve
and read back the dedicated app, exact issuer/client/subject and short session
settings. Only the parent management connection may revoke the observed new sid.
This process has no management credential, AWS route, TokenStore or file writes.
"""
from __future__ import annotations
from dataclasses import dataclass
import argparse,json,logging,math,re,selectors,sys,time,signal,resource
from .auth import AuthConfigurationError,AuthError,AuthUnconfigured,WorkOSConfig
from .workos import (TransportConfig,InvocationApproval,JWKSConfig,IssuerPinnedJWKS,
    CachedBearerVerifier,WorkOSPublicClient,WorkOSTransient,WorkOSReconnectRequired,
    WorkOSPending)

class SmokeStopped(AuthError):pass

@dataclass(frozen=True)
class SmokeConfig:
    issuer:str
    client_id:str
    owner_id:str
    owner_subject:str
    verification_uri:str
    jwks_url:str
    approved_until:int
    organization_mode:str='none'
    organization_id:str|None=None
    max_access_seconds:int=300
    max_local_seconds:int=3600
    signing_client_id:str|None=None
    def __post_init__(self):
        if self.max_access_seconds!=300 or self.max_local_seconds!=3600 or type(self.approved_until) is not int:
            raise AuthConfigurationError('smoke requires reviewed five-minute tokens and one-hour maximum')
        self.verifier_config()
    def verifier_config(self):
        return WorkOSConfig(issuer=self.issuer,audience=None,owner_id=self.owner_id,owner_subject=self.owner_subject,
            allowed_client_ids=frozenset([self.client_id]),organization_mode=self.organization_mode,
            organization_id=self.organization_id,token_profile='session',max_token_lifetime_seconds=self.max_access_seconds)

class MemorySmoke:
    def __init__(self,provider,verifier,config:SmokeConfig,*,clock=time.time,monotonic=time.monotonic):
        self.provider=provider;self.verifier=verifier;self.config=config;self.clock=clock;self.monotonic=monotonic
        budget=min(config.max_local_seconds,config.approved_until-int(clock()))
        if budget<=0:raise AuthUnconfigured('smoke invocation approval has expired')
        self.deadline=monotonic()+budget;self.phase='new';self._device=None;self._tokens=None
        self._principal=None;self._access_expiry=None;self._next_poll=monotonic();self._next_refresh=monotonic()
        self._observed_session=None;self._candidate=None;self._candidate_expires=0
    def __repr__(self):return 'MemorySmoke(credential_state=<redacted>, phase='+repr(self.phase)+')'
    def remaining(self):return max(0,self.deadline-self.monotonic())
    def _check(self):
        if self.remaining()<=0 or self.clock()>=self.config.approved_until:
            self.close();raise SmokeStopped('smoke hard deadline reached')
        if self.phase=='closed':raise SmokeStopped('smoke is closed')
    def _drop_secrets(self):
        self._device=None;self._tokens=None;self._candidate=None;self._candidate=None
        clear=getattr(self.provider,'clear_memory',None)
        if clear is not None:clear()
        # Python does not guarantee zeroization; ending this short-lived process
        # bounds retention. No heap/core dump is enabled by this harness.
    def close(self):
        self._drop_secrets();self.phase='closed';return {'phase':'closed','local_state_discarded':True,'provider_revocation_claimed':False}
    def start(self):
        self._check()
        if self.phase!='new':raise SmokeStopped('smoke login already started')
        auth=self.provider.start();self._check()
        if not re.fullmatch(r'[A-Za-z0-9-]{4,32}',auth.user_code) or auth.verification_uri!=self.config.verification_uri:
            self.close();raise SmokeStopped('unexpected device authorization contract')
        self._device=auth;self._next_poll=self.monotonic()+auth.interval;self.phase='awaiting_user'
        return {'phase':self.phase,'user_code':auth.user_code,'verification_uri':auth.verification_uri,
            'authorization_expires_in':min(auth.expires_in,int(self.remaining())),'local_deadline_seconds':int(self.remaining())}
    def _accept(self,tokens):
        self._check()
        verified=self.verifier.verify_details(tokens.access_token);self._check();p=verified.principal;c=self.config
        if (p.issuer!=c.issuer or p.client_id!=c.client_id or p.owner_id!=c.owner_id or p.subject!=c.owner_subject
            or p.organization_id!=c.organization_id or p.authentication_kind!='authkit_session' or p.actor_kind!='bearer_user'
            or (self._principal is not None and p!=self._principal)):
            self.close();raise SmokeStopped('unexpected verified identity contract')
        self._tokens=tokens;self._principal=p;self._observed_session=p.authentication_id
        self._access_expiry=verified.expires_at;self._device=None;self._candidate=None;self.phase='authenticated'
    def poll(self):
        self._check()
        if self.phase!='awaiting_user':return self.status()
        if self.monotonic()<self._next_poll:return {'phase':'awaiting_user','next_poll_in':math.ceil(self._next_poll-self.monotonic())}
        try:
            if self._candidate is not None:
                if self.monotonic()>=self._candidate_expires:self.close();raise SmokeStopped('pending verification expired')
                tokens=self._candidate
            else:
                tokens=self.provider.poll(self._device.device_code)
                if tokens is not None:self._candidate=tokens;self._candidate_expires=min(self.deadline,self.monotonic()+300)
            if tokens is None:
                self._next_poll=self.monotonic()+self._device.interval;return {'phase':'awaiting_user'}
            self._accept(tokens);return self.status()
        except WorkOSPending as exc:
            self._next_poll=self.monotonic()+exc.next_interval;return {'phase':'awaiting_user','next_poll_in':exc.next_interval}
        except WorkOSTransient as exc:
            self._next_poll=self.monotonic()+exc.retry_after;return {'phase':'provider_transient','retry_after':exc.retry_after,'session_retained':False}
        except AuthError:
            self.close();raise SmokeStopped('device authentication did not complete') from None
    def status(self):
        self._check()
        result={'phase':self.phase,'local_deadline_seconds':int(self.remaining()),'token_bodies_reported':False,'pending_verification':self._candidate is not None,
                'provider_revocation_visibility':'signed access JWT may remain verifiable until expiry; refresh denial is checked separately'}
        if self._principal:
            result.update(issuer=self._principal.issuer,client_id=self._principal.client_id,subject=self._principal.subject,
                          organization_id=self._principal.organization_id,session_kind=self._principal.authentication_kind,
                          session_id=self._observed_session,access_expires_at=self._access_expiry,
                          authenticated=self._tokens is not None and self.clock()<self._access_expiry)
        return result
    def refresh(self,*,verify_revoked=False):
        self._check()
        if self._tokens is None or self._principal is None:raise SmokeStopped('no verified smoke session to refresh')
        if self.monotonic()<self._next_refresh:return {'phase':'provider_transient','retry_after':math.ceil(self._next_refresh-self.monotonic()),'session_retained':True}
        old=self._tokens
        try:
            attempted=False
            if self._candidate is not None:
                if self.monotonic()>=self._candidate_expires:self.close();raise SmokeStopped('pending verification expired')
                tokens=self._candidate
            else:
                tokens=self.provider.refresh(old.refresh_token,expected_binding=old.identity_binding);attempted=True
                self._candidate=tokens;self._candidate_expires=min(self.deadline,self.monotonic()+300)
            rotated=tokens.refresh_token!=old.refresh_token
            self._accept(tokens)
            return {**self.status(),'refresh_verified':True,'refresh_rotated':rotated,'provider_refresh_attempted':attempted,
                    'revocation_confirmed':False if verify_revoked else None}
        except WorkOSTransient as exc:
            self._next_refresh=self.monotonic()+exc.retry_after
            return {**self.status(),'phase':'provider_transient','retry_after':exc.retry_after,
                    'session_retained':True,'authenticated':self.clock()<self._access_expiry}
        except WorkOSReconnectRequired as exc:
            # Only a typed exact HTTP400 invalid_grant proves the provider rejected
            # this refresh. Local binding or token validation errors do not count.
            from .workos import WorkOSInvalidGrant
            confirmed=verify_revoked and isinstance(exc,WorkOSInvalidGrant)
            session=self._observed_session;last_exp=self._access_expiry;self._drop_secrets()
            self.phase='revocation_confirmed' if confirmed else 'ended'
            return {'phase':self.phase,'session_id':session,'provider_refresh_denial_verified':confirmed,
                    'last_signed_access_expiry':last_exp,'credentials_discarded':True}
        except AuthError:
            self.close();raise SmokeStopped('refresh contract failed; revocation unconfirmed') from None


def configured_smoke(config:SmokeConfig,*,approved_invocation=False,clock=time.time,monotonic=time.monotonic,transport=None):
    if not approved_invocation:raise AuthUnconfigured('explicit approved live smoke invocation required')
    now=int(clock());deadline=min(config.approved_until,now+3600)
    approval=InvocationApproval(config.issuer,config.client_id,frozenset(['jwks','device_start','device_poll','refresh']),deadline)
    tc=TransportConfig(config.issuer,config.client_id,allow_live=True)
    keys=IssuerPinnedJWKS(JWKSConfig(config.issuer,config.client_id,'session',config.jwks_url,ttl_seconds=300,signing_client_id=config.signing_client_id),transport=transport,transport_config=tc,approval=approval,clock=clock)
    verifier=CachedBearerVerifier(config.verifier_config(),keys,clock=clock)
    provider=WorkOSPublicClient(tc,verifier,config.verification_uri,transport=transport,approval=approval,clock=clock,monotonic=monotonic)
    return MemorySmoke(provider,verifier,config,clock=clock,monotonic=monotonic)


def main(argv=None):
    p=argparse.ArgumentParser(description='Memory-only public-device authentication smoke; explicit reviewed invocation required')
    p.add_argument('--config',required=True);p.add_argument('--approved-invocation',action='store_true');a=p.parse_args(argv)
    logging.disable(logging.CRITICAL)
    # This Unix-only helper fails closed if process crash-dump suppression is unavailable.
    smoke=None
    def emit(value):print(json.dumps(value,separators=(',',':')),flush=True)
    try:
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        with open(a.config) as f:config=SmokeConfig(**json.load(f))
        smoke=configured_smoke(config,approved_invocation=a.approved_invocation)
        def deadline_alarm(signum,frame):raise SmokeStopped('smoke hard deadline reached')
        signal.signal(signal.SIGALRM,deadline_alarm);signal.setitimer(signal.ITIMER_REAL,smoke.remaining())
        emit(smoke.start());selector=selectors.DefaultSelector();selector.register(sys.stdin,selectors.EVENT_READ)
        while smoke.remaining()>0 and smoke.phase not in ('closed','ended','revocation_confirmed'):
            timeout=min(1,smoke.remaining());ready=selector.select(timeout)
            if ready:
                line=sys.stdin.readline()
                if not line:emit(smoke.close());break
                command=line.strip()
                if command=='status':emit(smoke.status())
                elif command=='refresh':emit(smoke.refresh())
                elif command=='verify-revoked':emit(smoke.refresh(verify_revoked=True))
                elif command=='close':emit(smoke.close())
                else:emit({'error':'unsupported_smoke_command'})
            elif smoke.phase=='awaiting_user' and smoke.monotonic()>=smoke._next_poll:
                result=smoke.poll()
                if result.get('phase') not in ('awaiting_user',):emit(result)
        if smoke.phase not in ('closed','ended','revocation_confirmed'):emit(smoke.close())
        return 0
    except (Exception,KeyboardInterrupt):
        if smoke is not None:smoke.close()
        emit({'error':'smoke_stopped','tokens_reported':False,'provider_revocation_claimed':False});return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        if smoke is not None:smoke._drop_secrets()
if __name__=='__main__':raise SystemExit(main())
