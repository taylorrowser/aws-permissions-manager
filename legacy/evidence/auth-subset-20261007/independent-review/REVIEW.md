# Independent WorkOS review

Scope: public WorkOS transport adapters and memory-only auth smoke. This is a narrow pre-live review, not production broker acceptance or proof of literal human presence.

No live WorkOS token request, sign-in, app mutation, credential provisioning, AWS call, deployment, purchase or push has been performed by this reviewer.

## Initial snapshot

Directory: `initial/`, copied before review on 2026-10-07.

SHA256:
- integration/workos.py: f372640db63f6bce0975c1471ec7576b24efc76dea56fd56c3ef86c03dedee27
- integration/auth.py: bf0499827fa5adfb946eb20e9efaabd63a48b414de25c8ddd0665553fc66e482
- tests/test_production_workos.py: 194daee739a134837385122a7e19fa01d659a30485ac419411eba54de5b98455
- WORKOS.md: 44272ebe7e03453ac983827a1563fb51f3bf08a9c41ccef7f164bc141c44ad02

Reproduced: 37 production transport tests, 31 imported auth-contract tests, and 16 durable-session tests, all passing against the installed workos 10.5.0 SDK. All use offline fixtures.

Independent initial adversarial findings:
1. JWKS HTTP503 after successful refresh is converted by `_accept` into terminal reconnect and causes binding loss. Reproduced by `adversarial.py ReviewAdversarial.test_jwks_outage_after_refresh_is_not_terminal`.
2. `refresh()` collapses HTTP400 invalid_grant, HTTP403 policy denial and malformed HTTP200 into the same exception. Smoke acceptance must require an explicit sanitized provider rejection signal, not generic reconnect. Reproduced in `adversarial.py`.
3. `max_sessions` can be exceeded by refresh with an untracked prior token and an expected principal already represented in the session map. Lower-priority cap hardening; does not block the one-session smoke in isolation.
4. Initial smoke only checks deadline outside provider calls, which is insufficient to guarantee hard one-hour memory/process lifetime during in-flight work. A watchdog/interrupt and post-call checks are needed.

CLI runtime note: the old CLI login loop did not consume new pending/slow-down/transient exceptions, and restart refresh omitted identity_binding. Implementer confirms these are in progress and the smoke must not be presented as full CLI acceptance.

## Primary-source verification

Read official workos-python current README, installed pinned 10.5.0 public_client.py, _base_client.py, and user_management/_resource.py. The public factory passes is_public=True, suppressing inherited WORKOS_API_KEY; explicit client/base URL/timeouts override environment defaults. Code and refresh requests are JSON using the exact current SDK methods, with max_retries=0.

- https://github.com/workos/workos-python
- https://workos.com/docs/authkit/cli-auth
- https://workos.com/docs/authkit/session-resilience
- https://workos.com/docs/reference/authkit/session-tokens
- https://workos.com/docs/authkit/applications
- https://workos.com/docs/authkit/sessions

Provider docs establish public client-ID-only device/refresh flows, a 30-second refresh replay grace, HTTP400 invalid_grant as a terminal refresh response, exact application client binding despite shared environment issuer, and app-specific session settings. These are not evidence that any live test passed.

## Final review

Pending exact frozen harness/transport snapshot and rerun. No live authorization is conferred by this report.

## Verified multi-application discovery (15:28 UTC)

Read-only public metadata was available through Firecrawl after the web reader did not support the API URL. Both the authenticated default application and an existing non-default CLI application resolve to the same environment-default issuer AND signing JWKS. See `evidence/verified-issuer-jwks.json` for exact sources and outputs. No token endpoint was invoked.

This exposes a configuration issue: initial `JWKSConfig` hardcodes the signing-source client to the token client. The new CLI client must remain an exact signed claim constraint, while the signing-source binding explicitly permits the separately verified environment-default client. New dedicated client discovery should be read back after approved creation. Neither source should be taken from unverified token claims.

## Final narrow acceptance (2026-10-07 15:44 UTC)

**Accepted for the proposed one-session, memory-only auth smoke, subject to separate user authorization and exact runtime configuration/app-setting read-back. This is code-review acceptance, not live invocation approval.**

Reviewed source fingerprint: `bc8f5165f33fcdd7ea5436c790ac3b2cb3bf65bdab2e45ac9b4ca14f77c2c29c`

All 11 scoped file hashes in `evidence/final-reviewed-manifest.json` match the isolated `final/` snapshot. Important files:
- `integration/workos.py`: `9d2d910c3619289d89c7fbcc48285edeafb6a739ea2722437898144c7c2f3d35`
- `integration/auth_smoke.py`: `5d92472f850dd0a2f76b02176dfcb78f3eade670224f326f526b221f6ec1c8c3`
- Current runbook: `integration/WORKOS.md` (the root WORKOS.md remains the earlier checkpoint)

Independent final run: 106 focused existing tests (45 transports, 14 smoke, 31 imported auth contracts, 16 durable-session contracts), plus nine separate adversarial checks; all pass, zero skipped. Full log: `evidence/final-focused-tests.txt`. The executable alarm was also behaviorally exercised against a blocking fake provider: interruption in 0.05 seconds, cleanup verified, output sanitized. No real credentials or live provider operation were involved in that exercise.

The initial defects are closed in this snapshot:
- Typed HTTP400 `invalid_grant` evidence is distinct from local, HTTP403, malformed-response and identity failures
- Adapter and harness each retain private pending candidates during JWKS verification failures; retry does not spend an already consumed device grant or lose uniquely rotated refresh credentials
- Unknown-key cooldown preserves legitimate new-key refresh candidates
- Session bindings remain capped; local provider-revocation cleanup discards pending candidates for the exact identity
- Signing-client/JWKS mapping is explicit and separate from token client_id
- Core dumps are disabled; executable process alarm and post-call checks bound local lifetime
- Compressed responses are rejected before decoding, redirects refused, default approved host routing preserved

Public-client no-key behavior, PKCE/state/client/issuer/subject binding, optional session jti versus stable typed sid, same-owner machine exclusion from browser grants, cache replacement/TTL/cooldown bounds, sanitized errors and dataclass repr were checked. Browser provenance is not literal human attestation.

### Runtime conditions still required

1. Separate explicit approval for the proposed new dedicated public-device app and one-session sign-in/refresh/revocation test
2. Read back exact new app/client with access 300 seconds, maximum session 3600 seconds and inactivity 1800 seconds before device authorization
3. Keep exact expected issuer `https://api.workos.com/user_management/client_01M0WAF72P892WH9FCE0VFRGWC`; signing_client_id is `client_01M0WAF72P892WH9FCE0VFRGWC` and JWKS is `https://api.workos.com/sso/jwks/client_01M0WAF72P892WH9FCE0VFRGWC`. Expected token client_id remains the dedicated app's returned client ID. No dynamic issuer broadening or token-driven discovery
4. Expected user is `user_01M0WD1S3ZX1R7KG75D2Z8SHTZ`; verification URI is `https://rousing-school-60.authkit.app/device`; keep explicit no-organization contract unless separately reviewed
5. Only the parent's existing management connection may verify/revoke the exact new session. Positive refresh must complete before revocation verification. Actual typed provider `invalid_grant` is the denial evidence
6. No AWS grant, production TokenStore, deployment, browser grant approval, new user/signup, paid feature or expanded access is covered

### Non-blocking telemetry caveat

`provider_refresh_attempted` marks calling the adapter. A transport-held pending candidate can be revalidated without another token POST, so that flag is not independently reliable dispatch evidence. The narrow negative proof remains sound because `WorkOSInvalidGrant` is emitted only for an actual guarded refresh endpoint response. Do not use the boolean to claim a provider POST occurred.

### Limits

Live sign-in, token issuance, rotation, provider revocation/propagation and post-revocation refresh denial remain NOT RUN. Signed JWTs may remain valid until expiry after provider revocation. Full CLI wiring, broker runtime, AWS integration, production durable storage and human-presence security are outside this acceptance. Python heap zeroization and OS swap behavior are not guaranteed. Any change to scoped source files requires hash reconciliation and affected review/tests before relying on this acceptance.
