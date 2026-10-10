"""Fail-closed, NON-LIVE WorkOS integration boundaries.

Only injected public JWKS are used; this module never fetches keys or contacts a
provider. Real issuers, subjects, audiences and application IDs have no defaults.
Connect bearer scopes are NOT application-owned AWS grant entitlements.

Official contracts checked 2026-10-07:
https://workos.com/docs/authkit/connect/token-claims
https://workos.com/docs/authkit/applications
https://workos.com/docs/reference/authkit/session-tokens
https://workos.com/docs/reference/authkit/authentication/get-authorization-url
https://workos.com/docs/reference/authkit/authentication

Connect requires an exact audience. AuthKit session tokens have a different
contract: configure token_profile='session', audience=None to require NO aud,
or explicitly configure an observed exact audience. Both require client_id even
when multiple applications share one issuer. A session verifier remains a bearer
verifier; only a verified, state+PKCE-bound callback creates a browser principal.

Browser state is deliberately single-process/in-memory for offline integration
QA. Production configuration is refused until a durable, atomic session/state/
challenge store and provider adapter have been implemented and reviewed. Never
expose the offline fixture-login helper in a normal production route.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Callable, Literal, Mapping, Protocol
from urllib.parse import urlencode, urlsplit

import jwt


class AuthError(Exception):
    """Sanitized authentication failure. Never includes provider/token input."""


class AuthUnconfigured(AuthError):
    """A provider or persistence adapter is intentionally unavailable."""


class AuthConfigurationError(AuthError):
    """An explicit contract is missing or inconsistent."""


@dataclass(frozen=True)
class Principal:
    subject: str
    owner_id: str
    client_id: str
    actor_kind: Literal['bearer_user', 'machine', 'human_browser']
    organization_id: str | None
    authentication_id: str
    issuer: str | None = None
    authentication_kind: str = 'offline'


def _identifier(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 512 and not any(
        c.isspace() or ord(c) < 32 for c in value)


def _safe_url(value: str, *, allow_loopback: bool = False) -> bool:
    try:
        if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 for c in value) or '\\' in value:
            return False
        parsed = urlsplit(value)
        parsed.port  # Reject malformed or out-of-range ports before URL construction.
        return (bool(parsed.hostname) and not parsed.username and not parsed.password
                and not parsed.fragment and not parsed.query and '*' not in value
                and (parsed.scheme == 'https' or (allow_loopback and
                     parsed.scheme == 'http' and parsed.hostname in
                     {'localhost', '127.0.0.1', '::1'})))
    except (TypeError, ValueError):
        return False


@dataclass(frozen=True)
class WorkOSConfig:
    issuer: str
    audience: str | None
    owner_id: str
    owner_subject: str
    allowed_client_ids: frozenset[str]
    organization_mode: Literal['none', 'required']
    organization_id: str | None = None
    machine_client_ids: frozenset[str] = frozenset()
    machine_audience: str | None = None
    token_profile: Literal['connect', 'session'] = 'connect'
    max_token_lifetime_seconds: int = 3600
    clock_skew_seconds: int = 0

    def __post_init__(self):
        if isinstance(self.allowed_client_ids, str) or isinstance(self.machine_client_ids, str):
            raise AuthConfigurationError('invalid WorkOS verification contract')
        object.__setattr__(self, 'allowed_client_ids', frozenset(self.allowed_client_ids))
        object.__setattr__(self, 'machine_client_ids', frozenset(self.machine_client_ids))
        if (not _safe_url(self.issuer) or not _identifier(self.owner_id)
                or not _identifier(self.owner_subject) or not self.allowed_client_ids
                or any(not _identifier(x) for x in self.allowed_client_ids)
                or not self.machine_client_ids <= self.allowed_client_ids
                or self.token_profile not in {'connect', 'session'}
                or (self.audience is not None and not _identifier(self.audience))
                or (self.token_profile == 'connect' and self.audience is None)
                or (self.token_profile == 'session' and self.machine_client_ids)
                or (self.machine_client_ids and not _identifier(self.machine_audience))
                or (not self.machine_client_ids and self.machine_audience is not None)
                or type(self.max_token_lifetime_seconds) is not int
                or not 1 <= self.max_token_lifetime_seconds <= 86400
                or type(self.clock_skew_seconds) is not int
                or not 0 <= self.clock_skew_seconds <= 60):
            raise AuthConfigurationError('invalid WorkOS verification contract')
        if (self.organization_mode not in {'none', 'required'}
                or (self.organization_mode == 'none' and self.organization_id is not None)
                or (self.organization_mode == 'required' and not _identifier(self.organization_id))):
            raise AuthConfigurationError('explicit organization contract required')


@dataclass(frozen=True)
class VerifiedToken:
    principal: Principal
    expires_at: int
    provider_token_id: str | None = field(default=None, repr=False)
    auth_time: int | None = None


class BearerVerifier:
    """Verifies supplied JWTs locally; never upgrades one to human_browser."""

    def __init__(self, config: WorkOSConfig | None = None,
                 jwks: Mapping | None = None, *, clock: Callable[[], float] = time.time):
        self.config = config
        self.clock = clock
        self._keys = {}
        if jwks is not None:
            try:
                if not isinstance(jwks.get('keys'), list) or not jwks['keys']:
                    raise ValueError()
                for key in jwks['keys']:
                    kid = key.get('kid')
                    if (not _identifier(kid) or kid in self._keys or key.get('kty') != 'RSA'
                            or key.get('alg', 'RS256') != 'RS256'
                            or key.get('use', 'sig') != 'sig'
                            or ('key_ops' in key and key['key_ops'] != ['verify'])
                            or 'd' in key):
                        raise ValueError()
                    parsed = jwt.PyJWK.from_dict(dict(key), algorithm='RS256')
                    if parsed.key.key_size < 2048:
                        raise ValueError()
                    self._keys[kid] = parsed.key
            except Exception:
                raise AuthConfigurationError('invalid public signing key set') from None

    def _configured(self) -> WorkOSConfig:
        if self.config is None or not self._keys:
            raise AuthUnconfigured('WorkOS bearer verification is not configured')
        return self.config

    def verify_authorization(self, header: str | None) -> Principal:
        if not isinstance(header, str) or not header.startswith('Bearer '):
            raise AuthError('bearer authentication required')
        token = header[7:]
        if not token or any(c.isspace() for c in token):
            raise AuthError('invalid bearer token')
        return self.verify(token)

    def verify(self, token: str) -> Principal:
        return self.verify_details(token).principal

    def verify_details(self, token: str) -> VerifiedToken:
        config = self._configured()
        try:
            if not isinstance(token, str) or not 1 <= len(token) <= 16384:
                raise ValueError()
            header = jwt.get_unverified_header(token)
            if (header.get('alg') != 'RS256' or not _identifier(header.get('kid'))
                    or header['kid'] not in self._keys
                    or any(k in header for k in ('jku', 'x5u', 'jwk', 'crit'))):
                raise ValueError()
            claims = jwt.decode(token, self._keys[header['kid']], algorithms=['RS256'],
                options={'require': ['iss', 'sub', 'client_id', 'exp', 'iat'],
                         'verify_aud': False, 'verify_iss': False,
                         'verify_exp': False, 'verify_iat': False, 'verify_nbf': False})
            # Type-strict comparisons avoid audience-array and bool-as-int ambiguity.
            if (claims['iss'] != config.issuer or not _identifier(claims['sub'])
                    or not _identifier(claims['client_id'])
                    or (config.token_profile=='connect' and not _identifier(claims.get('jti')))
                    or ('jti' in claims and not _identifier(claims['jti']))
                    or claims['client_id'] not in config.allowed_client_ids
                    or type(claims['exp']) is not int or type(claims['iat']) is not int
                    or 'act' in claims or 'impersonator' in claims):
                raise ValueError()
            now, skew = self.clock(), config.clock_skew_seconds
            if (claims['exp'] <= now - skew or claims['iat'] > now + skew
                    or claims['exp'] <= claims['iat']
                    or claims['exp'] - claims['iat'] > config.max_token_lifetime_seconds
                    or ('nbf' in claims and (type(claims['nbf']) is not int
                                           or claims['nbf'] > now + skew))):
                raise ValueError()
            client = claims['client_id']
            machine = client in config.machine_client_ids
            audience = config.machine_audience if machine else config.audience
            if (audience is None and 'aud' in claims) or (audience is not None and claims.get('aud') != audience):
                raise ValueError()
            if machine:
                if claims['sub'] != client or 'sid' in claims:
                    raise ValueError()
            elif claims['sub'] != config.owner_subject or not _identifier(claims.get('sid')):
                raise ValueError()
            org = claims.get('org_id')
            if config.organization_mode == 'none':
                if 'org_id' in claims:  # Absence is explicit; no guessed organization.
                    raise ValueError()
            elif org != config.organization_id:
                raise ValueError()
            auth_time=claims.get('auth_time')
            if auth_time is not None and (type(auth_time) is not int or auth_time>now+skew or auth_time>claims['iat']+skew):raise ValueError()
            kind='machine_client' if machine else 'authkit_session' if config.token_profile=='session' else 'connect_consent'
            principal = Principal(claims['sub'], config.owner_id, client,
                                  'machine' if machine else 'bearer_user', org, client if machine else claims['sid'],
                                  config.issuer,kind)
            return VerifiedToken(principal, claims['exp'],claims.get('jti'),auth_time)
        except Exception:
            raise AuthError('invalid bearer token') from None


@dataclass(frozen=True)
class CodeExchangeResult:
    access_token: str = field(repr=False)


class AuthorizationCodeExchange(Protocol):
    """Trusted future adapter; bind exchange to these exact client/redirect/PKCE values.

    The adapter owns credentials and HTTPS transport, validates provider failures,
    and returns only the access token, never logging tokens or authorization codes.
    Implementing this Protocol does not authorize live provider access.
    """
    def exchange(self, *, code: str, client_id: str, redirect_uri: str,
                 code_verifier: str) -> CodeExchangeResult: ...


class UnconfiguredCodeExchange:
    def exchange(self, *, code: str, client_id: str, redirect_uri: str,
                 code_verifier: str) -> CodeExchangeResult:
        raise AuthUnconfigured('WorkOS authorization-code exchange is not configured')


@dataclass(frozen=True)
class BrowserConfig:
    client_id: str
    origin: str
    redirect_uri: str
    authorization_endpoint: str
    production: bool = True
    session_ttl: int = 600
    login_ttl: int = 300
    challenge_ttl: int = 60
    approval_reauth_seconds: int | None = None

    def __post_init__(self):
        if (not _identifier(self.client_id)
                or not _safe_url(self.origin, allow_loopback=not self.production)
                or urlsplit(self.origin).path
                or not _safe_url(self.redirect_uri, allow_loopback=not self.production)
                or not self.redirect_uri.startswith(self.origin + '/')
                or not _safe_url(self.authorization_endpoint)
                or type(self.production) is not bool
                or type(self.session_ttl) is not int or not 1 <= self.session_ttl <= 900
                or type(self.login_ttl) is not int or not 1 <= self.login_ttl <= 300
                or type(self.challenge_ttl) is not int or not 1 <= self.challenge_ttl <= 120
                or (self.approval_reauth_seconds is not None and (type(self.approval_reauth_seconds) is not int or not 1<=self.approval_reauth_seconds<=300))):
            raise AuthConfigurationError('invalid browser authentication contract')


@dataclass(frozen=True)
class LoginStart:
    authorization_url: str = field(repr=False)
    state_cookie: str = field(repr=False)


@dataclass(frozen=True)
class BrowserSession:
    principal: Principal
    csrf: str = field(repr=False)
    expires_at: int
    origin: str
    _key: str = field(repr=False)
    auth_time: int | None = None
    approval_binding: tuple[str,int,str] | None = field(default=None,repr=False)


@dataclass(frozen=True)
class BrowserLogin:
    session_cookie: str = field(repr=False)
    csrf: str = field(repr=False)
    principal: Principal
    expires_at: int


@dataclass(frozen=True, repr=False)
class _PendingLogin:
    state: str
    verifier: str
    expires_at: int
    approval_binding: tuple[str,int,str] | None = None
    requested_auth_at: int | None = None


@dataclass(frozen=True, repr=False)
class _Challenge:
    session_key: str
    request_id: str
    revision: int
    digest: str
    expires_at: int


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _secret(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{32,256}', value))


class BrowserAuth:
    """Browser-client provenance with atomic, injectable server-side state.

    This cannot prove literal human presence when an agent controls the browser.
    Production decisions remain user-operated; transaction-bound reauthentication
    or WebAuthn user verification requires a separately reviewed integration.
    """
    def __init__(self, config: BrowserConfig | None = None,
                 token_verifier: BearerVerifier | None = None,
                 exchange: AuthorizationCodeExchange | None = None, *,
                 offline_mode: bool = False, clock: Callable[[], float] = time.time,
                 state_store=None):
        from .session_store import MemoryBrowserState
        if config is not None and config.production and (state_store is None or not state_store.production_ready):
            raise AuthUnconfigured('production browser authentication requires an approved durable atomic session store')
        self.config=config;self.token_verifier=token_verifier or BearerVerifier()
        self.exchange=exchange or UnconfiguredCodeExchange();self.offline_mode=offline_mode;self.clock=clock
        self.state_store=state_store or MemoryBrowserState()
        from weakref import WeakValueDictionary
        self._validated_sessions=WeakValueDictionary()
        # Kept only for compatibility with offline fixture assertions, never used as authority.
        self._pending=getattr(self.state_store,'pending',{})
        self._sessions=getattr(self.state_store,'sessions',{})
        self._challenges=getattr(self.state_store,'challenges',{})

    @property
    def cookie_name(self):return '__Host-broker' if self.config is None or self.config.production else 'broker-offline-session'
    @property
    def state_cookie_name(self):return '__Host-broker-login' if self.config is None or self.config.production else 'broker-offline-login'
    @property
    def cookie_options(self):
        return {'secure':self.config is None or self.config.origin.startswith('https://'),'httponly':True,'samesite':'strict','path':'/','max_age':self.config.session_ttl if self.config else 600}
    @property
    def state_cookie_options(self):return {**self.cookie_options,'samesite':'lax','max_age':self.config.login_ttl if self.config else 300}
    def _configured(self):
        if self.config is None:raise AuthUnconfigured('browser authentication is not configured')
        vc=self.token_verifier._configured()
        if vc.token_profile!='session' or self.config.client_id not in vc.allowed_client_ids or self.config.client_id in vc.machine_client_ids:
            raise AuthConfigurationError('browser requires its exact AuthKit session client')
        return self.config
    def _context(self):
        import json
        self._configured();vc=self.token_verifier.config
        # Context includes all identity/client/organization bindings. Reconfiguration
        # invalidates old state, rather than silently adopting another app's session.
        return hashlib.sha256(json.dumps([vc.issuer,vc.audience,vc.owner_id,vc.owner_subject,vc.organization_mode,vc.organization_id,vc.token_profile,self.config.client_id,self.config.origin,self.config.redirect_uri,self.config.approval_reauth_seconds],separators=(',',':')).encode()).hexdigest()
    def start_login(self):return self._start_login()
    def start_approval_login(self,request_id,revision,digest):
        self._check_binding(request_id,revision,digest)
        if self.config is None or self.config.approval_reauth_seconds is None:raise AuthUnconfigured('transaction reauthentication is not configured')
        return self._start_login((request_id,revision,digest))
    def _start_login(self,approval_binding=None):
        config=self._configured()
        if isinstance(self.exchange,UnconfiguredCodeExchange):raise AuthUnconfigured('WorkOS authorization-code exchange is not configured')
        state,cookie,verifier=(secrets.token_urlsafe(32) for _ in range(3))
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        self.state_store.create_login(_hash_secret(cookie),_PendingLogin(state,verifier,int(self.clock())+config.login_ttl,approval_binding,int(self.clock()) if approval_binding else None),self._context(),int(self.clock()))
        params={'client_id':config.client_id,'redirect_uri':config.redirect_uri,'response_type':'code','provider':'authkit','state':state,'code_challenge':challenge,'code_challenge_method':'S256','max_age':0}
        if self.token_verifier.config.organization_id is not None:params['organization_id']=self.token_verifier.config.organization_id
        return LoginStart(config.authorization_endpoint+'?'+urlencode(params),cookie)
    def finish_login(self,*,code,state,state_cookie):
        config=self._configured()
        if not _secret(state) or not _secret(state_cookie) or not isinstance(code,str) or not 1<=len(code)<=4096 or any(c.isspace() for c in code):raise AuthError('invalid browser login callback')
        pending=self.state_store.consume_login(_hash_secret(state_cookie),self._context(),int(self.clock()))
        if pending is None or not hmac.compare_digest(pending.state,state):raise AuthError('invalid browser login callback')
        try:
            result=self.exchange.exchange(code=code,client_id=config.client_id,redirect_uri=config.redirect_uri,code_verifier=pending.verifier)
            if not isinstance(result,CodeExchangeResult):raise AuthError('invalid browser login callback')
            verified=self.token_verifier.verify_details(result.access_token)
            if pending.approval_binding is not None and (verified.auth_time is None or verified.auth_time<pending.requested_auth_at or self.clock()-verified.auth_time>config.approval_reauth_seconds):
                raise AuthError('fresh transaction-bound authentication required')
            return self._create_session(verified.principal,verified.expires_at,auth_time=verified.auth_time,approval_binding=pending.approval_binding)
        except AuthUnconfigured:raise AuthUnconfigured('WorkOS authorization-code exchange is not configured') from None
        except Exception:raise AuthError('invalid browser login callback') from None
    def _check_principal(self,principal,*,browser):
        self._configured();vc=self.token_verifier.config
        if (not isinstance(principal,Principal) or principal.actor_kind!=('human_browser' if browser else 'bearer_user')
            or principal.client_id!=self.config.client_id or principal.subject!=vc.owner_subject or principal.owner_id!=vc.owner_id
            or principal.organization_id!=vc.organization_id or not _identifier(principal.authentication_id)
            or (principal.issuer!=vc.issuer and not (self.offline_mode and principal.issuer is None))):
            raise AuthError('owner browser authentication required')
    def _create_session(self,principal,token_expires_at,*,auth_time=None,approval_binding=None):
        self._check_principal(principal,browser=False)
        cookie,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32);key=_hash_secret(cookie)
        principal=replace(principal,actor_kind='human_browser',authentication_id='browser_'+secrets.token_hex(16),authentication_kind='browser_session')
        expires=min(int(self.clock())+self.config.session_ttl,token_expires_at)
        if expires<=self.clock():raise AuthError('owner browser authentication required')
        session=BrowserSession(principal,csrf,expires,self.config.origin,key,auth_time,approval_binding)
        self.state_store.create_session(key,session,self._context(),int(self.clock()))
        return BrowserLogin(cookie,csrf,principal,expires)
    def fixture_login(self,principal):
        if not self.offline_mode or self.config is None or self.config.production:raise AuthUnconfigured('offline fixture browser login is disabled')
        return self._create_session(principal,int(self.clock())+self.config.session_ttl)
    def human_session(self,cookie):
        self._configured()
        if not _secret(cookie):raise AuthError('owner browser authentication required')
        session=self.state_store.get_session(_hash_secret(cookie),self._context(),int(self.clock()))
        if isinstance(session,BrowserSession):self._validated_sessions[id(session)]=session
        return self._check_session(session)
    def _check_session(self,session):
        if not isinstance(session,BrowserSession) or self._validated_sessions.get(id(session)) is not session or session.expires_at<=self.clock() or session.origin!=self.config.origin:raise AuthError('owner browser authentication required')
        actual=self.state_store.get_session(session._key,self._context(),int(self.clock()))
        if actual!=session:raise AuthError('owner browser authentication required')
        self._check_principal(session.principal,browser=True);return session
    @staticmethod
    def _check_binding(request_id,revision,digest):
        if not _identifier(request_id) or type(revision) is not int or revision<1 or not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest):raise AuthError('invalid approval binding')
    def approval_session_ready(self,session,request_id,revision,digest):
        self._check_session(session)
        age=self.config.approval_reauth_seconds
        return age is None or (session.approval_binding==(request_id,revision,digest) and session.auth_time is not None and 0<=self.clock()-session.auth_time<=age)
    def _require_step_up(self,session,request_id,revision,digest):
        if not self.approval_session_ready(session,request_id,revision,digest):raise AuthError('fresh transaction-bound authentication required')
    def new_challenge(self,session,request_id,revision,digest):
        self._configured();self._check_binding(request_id,revision,digest);self._require_step_up(session,request_id,revision,digest)
        challenge=secrets.token_urlsafe(32)
        value=_Challenge(session._key,request_id,revision,digest,min(session.expires_at,int(self.clock())+self.config.challenge_ttl))
        self.state_store.create_challenge(_hash_secret(challenge),value,session,self._context(),int(self.clock()));return challenge
    def consume_challenge(self,session,origin,csrf,challenge,request_id,revision,digest):
        self._configured();self._check_binding(request_id,revision,digest);self._require_step_up(session,request_id,revision,digest)
        if origin!=self.config.origin or not _secret(csrf) or not hmac.compare_digest(csrf,session.csrf) or not _secret(challenge):raise AuthError('invalid browser approval proof')
        return self.state_store.consume_challenge(_hash_secret(challenge),session,request_id,revision,digest,self._context(),int(self.clock()))
    def logout(self,cookie):
        if _secret(cookie):self.state_store.revoke_session(_hash_secret(cookie),self._context())


@dataclass(frozen=True)
class DeviceAuthorization:
    device_code: str = field(repr=False)
    user_code: str = field(repr=False)
    verification_uri: str
    expires_in: int
    interval: int


@dataclass(frozen=True)
class DeviceTokens:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_in: int
    identity_binding: dict = field(default_factory=dict,repr=False)


class DeviceAuth(Protocol):
    """CLI device flow boundary; no provider calls or secret storage implemented.

    A real adapter must enforce polling interval/slow_down, expiration, exact
    client/resource, refresh rotation and revocation, and use secure OS storage.
    Device tokens must pass BearerVerifier and can never become browser sessions.
    """
    def start(self) -> DeviceAuthorization: ...
    def poll(self, device_code: str) -> DeviceTokens | None: ...
    def refresh(self, refresh_token: str, *, expected_binding: dict | None = None) -> DeviceTokens: ...
    def revoke(self, refresh_token: str, *, expected_binding: dict | None = None) -> None: ...


class UnconfiguredDeviceAuth:
    def start(self) -> DeviceAuthorization:
        raise AuthUnconfigured('WorkOS CLI device authentication is not configured')

    def poll(self, device_code: str) -> DeviceTokens | None:
        raise AuthUnconfigured('WorkOS CLI device authentication is not configured')

    def refresh(self, refresh_token: str, *, expected_binding: dict | None = None) -> DeviceTokens:
        raise AuthUnconfigured('WorkOS CLI device authentication is not configured')

    def revoke(self, refresh_token: str, *, expected_binding: dict | None = None) -> None:
        raise AuthUnconfigured('WorkOS CLI device authentication is not configured')
