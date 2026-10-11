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
                options={'require': ['iss', 'sub', 'client_id', 'jti', 'exp', 'iat'],
                         'verify_aud': False, 'verify_iss': False,
                         'verify_exp': False, 'verify_iat': False, 'verify_nbf': False})
            # Type-strict comparisons avoid audience-array and bool-as-int ambiguity.
            if (claims['iss'] != config.issuer or not _identifier(claims['sub'])
                    or not _identifier(claims['client_id']) or not _identifier(claims['jti'])
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
            principal = Principal(claims['sub'], config.owner_id, client,
                                  'machine' if machine else 'bearer_user', org, claims['jti'])
            return VerifiedToken(principal, claims['exp'])
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
                or type(self.challenge_ttl) is not int or not 1 <= self.challenge_ttl <= 120):
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
    """Opaque browser-only sessions and atomic one-use approval challenges.

    Cookie bytes are capabilities: routes must never accept them via Authorization,
    query strings, public fixture headers or body identity fields. Serve CSRF only
    to the authenticated same-origin page and disable caching of auth responses.
    """
    def __init__(self, config: BrowserConfig | None = None,
                 token_verifier: BearerVerifier | None = None,
                 exchange: AuthorizationCodeExchange | None = None, *,
                 offline_mode: bool = False, clock: Callable[[], float] = time.time):
        if config is not None and config.production:
            raise AuthUnconfigured('production browser authentication requires a durable atomic session store')
        self.config = config
        self.token_verifier = token_verifier or BearerVerifier()
        self.exchange = exchange or UnconfiguredCodeExchange()
        self.offline_mode = offline_mode
        self.clock = clock
        self._lock = threading.RLock()
        self._pending: dict[str, _PendingLogin] = {}
        self._sessions: dict[str, BrowserSession] = {}
        self._challenges: dict[str, _Challenge] = {}

    @property
    def cookie_name(self) -> str:
        return '__Host-broker' if self.config is None or self.config.production else 'broker-offline-session'

    @property
    def state_cookie_name(self) -> str:
        return '__Host-broker-login' if self.config is None or self.config.production else 'broker-offline-login'

    @property
    def cookie_options(self) -> dict:
        return {'secure': self.config is None or self.config.origin.startswith('https://'),
                'httponly': True, 'samesite': 'strict', 'path': '/',
                'max_age': self.config.session_ttl if self.config else 600}

    @property
    def state_cookie_options(self) -> dict:
        # OAuth's top-level cross-site GET must carry this ephemeral cookie.
        return {**self.cookie_options, 'samesite': 'lax',
                'max_age': self.config.login_ttl if self.config else 300}

    def _configured(self) -> BrowserConfig:
        if self.config is None:
            raise AuthUnconfigured('browser authentication is not configured')
        verifier_config = self.token_verifier._configured()
        if (verifier_config.token_profile != 'session'
                or self.config.client_id not in verifier_config.allowed_client_ids
                or self.config.client_id in verifier_config.machine_client_ids):
            raise AuthConfigurationError('browser requires its exact AuthKit session client')
        return self.config

    def _purge(self):
        now = self.clock()
        for store in (self._pending, self._sessions, self._challenges):
            for key, value in list(store.items()):
                if value.expires_at <= now:
                    del store[key]

    def start_login(self) -> LoginStart:
        config = self._configured()
        if isinstance(self.exchange, UnconfiguredCodeExchange):
            raise AuthUnconfigured('WorkOS authorization-code exchange is not configured')
        state, cookie, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        with self._lock:
            self._purge()
            self._pending[_hash_secret(cookie)] = _PendingLogin(state, verifier, int(self.clock()) + config.login_ttl)
        params = {'client_id': config.client_id, 'redirect_uri': config.redirect_uri,
                  'response_type': 'code', 'provider': 'authkit', 'state': state,
                  'code_challenge': challenge, 'code_challenge_method': 'S256', 'max_age': 0}
        org = self.token_verifier.config.organization_id
        if org is not None:
            params['organization_id'] = org
        return LoginStart(config.authorization_endpoint + '?' + urlencode(params), cookie)

    def finish_login(self, *, code: str, state: str, state_cookie: str) -> BrowserLogin:
        config = self._configured()
        if (not _secret(state) or not _secret(state_cookie) or not isinstance(code, str)
                or not 1 <= len(code) <= 4096 or any(c.isspace() for c in code)):
            raise AuthError('invalid browser login callback')
        with self._lock:
            self._purge()
            # Consume before exchange: retries/replayed codes never create sessions.
            pending = self._pending.pop(_hash_secret(state_cookie), None)
        if pending is None or not hmac.compare_digest(pending.state, state):
            raise AuthError('invalid browser login callback')
        try:
            result = self.exchange.exchange(code=code, client_id=config.client_id,
                                            redirect_uri=config.redirect_uri,
                                            code_verifier=pending.verifier)
            if not isinstance(result, CodeExchangeResult):
                raise AuthError('invalid browser login callback')
            verified = self.token_verifier.verify_details(result.access_token)
            return self._create_session(verified.principal, verified.expires_at)
        except AuthUnconfigured:
            raise AuthUnconfigured('WorkOS authorization-code exchange is not configured') from None
        except Exception:
            raise AuthError('invalid browser login callback') from None

    def _check_principal(self, principal: Principal, *, browser: bool):
        config = self._configured()
        vc = self.token_verifier.config
        expected_kind = 'human_browser' if browser else 'bearer_user'
        if (not isinstance(principal, Principal) or principal.actor_kind != expected_kind
                or principal.client_id != config.client_id or principal.subject != vc.owner_subject
                or principal.owner_id != vc.owner_id or principal.organization_id != vc.organization_id
                or not _identifier(principal.authentication_id)):
            raise AuthError('owner browser authentication required')

    def _create_session(self, principal: Principal, token_expires_at: int) -> BrowserLogin:
        self._check_principal(principal, browser=False)
        cookie, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        key = _hash_secret(cookie)
        principal = replace(principal, actor_kind='human_browser',
                            authentication_id='browser_' + secrets.token_hex(16))
        expires = min(int(self.clock()) + self.config.session_ttl, token_expires_at)
        if expires <= self.clock():
            raise AuthError('owner browser authentication required')
        session = BrowserSession(principal, csrf, expires, self.config.origin, key)
        with self._lock:
            self._purge()
            self._sessions[key] = session
        return BrowserLogin(cookie, csrf, principal, expires)

    def fixture_login(self, principal: Principal) -> BrowserLogin:
        """EXPLICIT OFFLINE FIXTURE ONLY; caller is an internal test/demo adapter.

        This does not authenticate a person. Never wire it to a production route,
        bearer token conversion, client-selected identity or request-header switch.
        """
        if not self.offline_mode or self.config is None or self.config.production:
            raise AuthUnconfigured('offline fixture browser login is disabled')
        return self._create_session(principal, int(self.clock()) + self.config.session_ttl)

    def human_session(self, cookie: str | None) -> BrowserSession:
        self._configured()
        if not _secret(cookie):
            raise AuthError('owner browser authentication required')
        with self._lock:
            self._purge()
            session = self._sessions.get(_hash_secret(cookie))
            return self._check_session(session)

    def _check_session(self, session: BrowserSession | None) -> BrowserSession:
        if (not isinstance(session, BrowserSession) or self._sessions.get(session._key) is not session
                or session.expires_at <= self.clock() or session.origin != self.config.origin):
            raise AuthError('owner browser authentication required')
        self._check_principal(session.principal, browser=True)
        return session

    @staticmethod
    def _check_binding(request_id: str, revision: int, digest: str):
        if (not _identifier(request_id) or type(revision) is not int or revision < 1
                or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)):
            raise AuthError('invalid approval binding')

    def new_challenge(self, session: BrowserSession, request_id: str,
                      revision: int, digest: str) -> str:
        self._configured()
        self._check_binding(request_id, revision, digest)
        with self._lock:
            self._purge()
            self._check_session(session)
            challenge = secrets.token_urlsafe(32)
            self._challenges[_hash_secret(challenge)] = _Challenge(
                session._key, request_id, revision, digest,
                min(session.expires_at, int(self.clock()) + self.config.challenge_ttl))
            return challenge

    def consume_challenge(self, session: BrowserSession, origin: str, csrf: str,
                          challenge: str, request_id: str, revision: int, digest: str) -> Principal:
        self._configured()
        self._check_binding(request_id, revision, digest)
        with self._lock:
            self._purge()
            self._check_session(session)
            if (origin != self.config.origin or not _secret(csrf)
                    or not hmac.compare_digest(csrf, session.csrf) or not _secret(challenge)):
                raise AuthError('invalid browser approval proof')
            proof = self._challenges.pop(_hash_secret(challenge), None)
            if (proof is None or proof.session_key != session._key or proof.request_id != request_id
                    or proof.revision != revision or not hmac.compare_digest(proof.digest, digest)):
                raise AuthError('invalid browser approval proof')
            return session.principal

    def logout(self, cookie: str | None):
        if not _secret(cookie):
            return
        key = _hash_secret(cookie)
        with self._lock:
            self._sessions.pop(key, None)
            for challenge, proof in list(self._challenges.items()):
                if proof.session_key == key:
                    del self._challenges[challenge]


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


class DeviceAuth(Protocol):
    """CLI device flow boundary; no provider calls or secret storage implemented.

    A real adapter must enforce polling interval/slow_down, expiration, exact
    client/resource, refresh rotation and revocation, and use secure OS storage.
    Device tokens must pass BearerVerifier and can never become browser sessions.
    """
    def start(self) -> DeviceAuthorization: ...
    def poll(self, device_code: str) -> DeviceTokens | None: ...
    def refresh(self, refresh_token: str) -> DeviceTokens: ...
    def revoke(self, refresh_token: str) -> None: ...


class UnconfiguredDeviceAuth:
    def start(self) -> DeviceAuthorization:
        raise AuthUnconfigured('WorkOS CLI device authentication is not configured')

    def poll(self, device_code: str) -> DeviceTokens | None:
        raise AuthUnconfigured('WorkOS CLI device authentication is not configured')

    def refresh(self, refresh_token: str) -> DeviceTokens:
        raise AuthUnconfigured('WorkOS CLI device authentication is not configured')

    def revoke(self, refresh_token: str) -> None:
        raise AuthUnconfigured('WorkOS CLI device authentication is not configured')
