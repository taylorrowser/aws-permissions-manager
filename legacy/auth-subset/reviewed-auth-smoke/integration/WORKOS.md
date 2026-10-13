# WorkOS transports and memory-only auth smoke

Status: concrete adapters tested offline; live invocation still requires separate explicit approval. This runbook is not approval to create an app, sign in, fetch tokens, alter settings, revoke a session or deploy the broker.

## Components and dependencies

- `workos.py`: official WorkOS Python SDK 10.5.0 public PKCE code and refresh exchange, guarded SDK backend, documented public AuthKit device authorization/poll endpoints, issuer-pinned JWKS cache and strict JWT verification
- `auth_smoke.py`: isolated, memory-only one-session diagnostic with a one-hour process alarm; it does not use CLI TokenStore, browser approval routes, broker grants or AWS
- `auth.py`/`session_store.py`: strict identity contracts and separate browser approval session boundaries; durable SQLite is an encrypted reference implementation, not a Lambda store or production authority boundary

Verified runtime for offline checks: workos 10.5.0 and httpx2 2.13.1; these were installed in `/tmp/permission-broker-workos-sdk`. Main pinned requirements are in `integration/requirements.txt`. The SDK uses its explicitly constructed public client; no API key/client secret is read from environment or sent. The host's proxy/CA network routing is preserved by default.

Run only offline tests unless the live gate below has separately been satisfied:

```
PYTHONPATH=/tmp/permission-broker-workos-sdk:/tmp/permission-broker-sdk:. python3 -m unittest discover -s tests -p test_production_workos.py -v
PYTHONPATH=/tmp/permission-broker-workos-sdk:/tmp/permission-broker-sdk:. python3 -m unittest discover -s tests -p test_production_auth_smoke.py -v
```

On another executor install reviewed requirements normally instead of relying on build-local /tmp paths.

## Profiles and exact configuration

Browser AuthKit session tokens and Connect user/machine tokens are different profiles. AuthKit sid is a session ID; Connect sid is consent identity; machine tokens have no sid and bind their exact client. Provider jti is optional audit metadata for the session profile, never a stable connection ID. Continuity includes configured issuer, token client, subject, organization/no-organization contract and typed stable identity. WorkOS scopes never substitute for broker-owned entitlements.

Explicit issuer and JWKS mapping must come from a verified provider contract/discovery document. Multiple apps can share the environment's issuer and signing client while each access token carries its current app client_id. Never substitute the environment signing-client ID for the expected token client. No token-controlled issuer/jku URL is fetched.

## Separate live-smoke gate

Before any live call, the parent must obtain approval, create/read back the exact dedicated public AuthKit CLI app if authorized, verify its 300-second access TTL, 3600-second maximum session and 1800-second inactivity setting, and record the exact new app/client, expected subject, observed issuer, signing client/JWKS URL and verification URI. No callback, API key, Connect M2M, AWS grant or organization change is part of this smoke.

`SmokeConfig` consumes only non-secret metadata: issuer, client_id, owner_id, owner_subject, verification_uri, jwks_url, signing_client_id, approved_until (absolute Unix seconds), organization_mode (normally explicit none), organization_id, max_access_seconds=300 and max_local_seconds=3600. Unknown fields are rejected. Do not put tokens, keys or codes in its file. Copying the review proposal with placeholders is not a valid runtime configuration.

Only after independent helper review and explicit invocation authorization, the trusted parent may start:

```
PYTHONPATH=/tmp/permission-broker-workos-sdk:. python3 -m integration.auth_smoke --config <verified-nonsecret-config.json> --approved-invocation
```

The flag records an already-approved host invocation; it does not create user approval. The transport also binds permitted operations, exact issuer/client and expiry. The Unix helper disables core dumps, installs a SIGALRM hard process deadline and checks deadlines after blocking calls. It fails closed if setup or configuration is invalid.

The helper emits the verified verification URI and one-time user code, then polls with pending/slow_down handling. It never displays the device code. After sign-in it reports only safe status, exact typed AuthKit session ID and signed access expiry. Supported stdin commands are status, refresh, verify-revoked and close. `refresh` checks stable identity and rotation. Only the parent uses the existing management connection to verify and revoke that exact newly observed app/user/session. `verify-revoked` makes a real bounded refresh attempt and accepts only exact provider invalid_grant as negative evidence; no generic/local denial is sufficient. The helper never calls management revocation itself. A transient response is inconclusive and retains private state only until the hard local deadline. Closing locally does not claim provider logout.

All credentials remain in process memory. No credential bodies enter stdout, stderr, source, files or artifacts. Python heap zeroization and host swap behavior are not guaranteed; end the process. The general CLI's private token file is a different workflow and is not used in this diagnostic. Do not invoke a real AWS credential-process command through a model-visible capture.

Sources checked: https://workos.com/docs/authkit/cli-auth ; https://workos.com/docs/authkit/session-resilience ; https://workos.com/docs/authkit/applications ; https://workos.com/docs/authkit/connect/token-claims ; https://workos.com/docs/reference/authkit/session-tokens ; https://workos.com/docs/authkit/reauthentication ; https://github.com/workos/workos-python

## Independent-review corrections and smoke scope

An actual token-client ID is distinct from the environment signing-client ID in a multi-application environment. `JWKSConfig.signing_client_id` explicitly pins the reviewed signing source while `client_id` still binds the expected token/application. Both come from trusted configuration/public discovery checked outside token validation. No unverified JWT claim triggers discovery or chooses a key URL.

After a token exchange succeeds but key verification is temporarily unavailable (including a legitimate unknown-key cooldown), the adapter retains the new pair only in a bounded, redacted, memory-only pending-verification record. It is tied to the prior verified identity and original refresh credential hash. Retry rechecks that candidate before doing another token exchange; it neither authorizes unverified access nor loses the uniquely rotated refresh token. The candidate expires after at most 300 seconds and is discarded on local revocation or process close. This is not durable restart recovery of an unverified pair. The documented 30-second provider grace period does not extend access-token validity.

`WorkOSInvalidGrant` means only an actual refresh endpoint response HTTP 400 with exact OAuth error `invalid_grant`. Generic reconnect, local validation, unknown signing keys, HTTP 403, malformed responses, expired invocation approval and network failure do not prove provider revocation. Already signed access tokens can remain cryptographically verifiable until expiry after WorkOS session revocation; immediate provider revocation visibility needs a separately reviewed authenticated event/online check.

The separate `auth_smoke.py` harness never imports CLI TokenStore, stores credentials in files, prints provider response bodies or calls management revocation. It emits a verified user code/URI and minimal verified identity/status only, enforces exact issuer/token client/user/no-org contracts, limits signed access-token TTL to the reviewed 300 seconds, and installs a one-hour process alarm plus core-dump suppression. Only the parent management connection may revoke the exact observed newly created AuthKit session. The helper then checks actual provider `invalid_grant`; any other result is explicitly inconclusive. Python heap zeroization is not claimed. No live invocation is allowed until the exact helper/configuration and requested sign-in have been approved.

Network routing honors host environment proxy/CA settings by default. No alternate-route retry is used. The transport requests identity encoding and rejects compressed responses before decoding, bounds streamed response bytes, refuses redirects and disables SDK automatic token-exchange retries. Live discovery, client prompt behavior, provider propagation, authenticated webhook status and full broker operation remain separate gates.

The memory-only harness also keeps a provider-returned pair privately if its second local verification encounters a transient failure. Retry verifies that candidate without repeating an already consumed device grant or rotating the old refresh token again. Neither this pending pair nor the transport's pending pair counts as authenticated authority; signed expiry, exact stable identity and the local hard deadline still apply. Safe status reports whether a refresh network attempt actually occurred.
