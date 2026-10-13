# AWS Permissions CLI: owner-run authentication check

Prepared October 9, 2026. **The live token flow has not been run.** This package was reviewed and tested offline. It is ready for the owner to run later; no additional sign-in is needed just to inspect it.

## What this checks

One local process requests one device authorization, verifies the resulting signed access token, exchanges its refresh token once, and attempts to end that exact test session. It needs no API key, client secret, npm package, AWS credentials, or application-setting changes.

The helper is fixed to the approved AWS Permissions CLI application and owner account. It does not perform AWS or IAM operations. It has no token input/import option: an old cloud-generated device secret should not be copied into it.

The previous browser approval cannot complete a new local process's flow. When you choose to run this helper, it creates one fresh code with its polling process already running. Use the browser where you are already signed in if convenient; WorkOS may still ask you to authenticate. Do not repeat a hosted sign-in independently of the running helper.

## Run it only when ready

Use your own private terminal outside assistant tools, screen sharing, terminal recording, debuggers, and HTTP/TLS tracing. Keep the terminal open until cleanup completes.

Requirements: an existing Node.js **18 or newer** installation and outbound HTTPS access to `api.workos.com`. The browser visits only the verified AuthKit device page. No installation is performed by these files.

**Use Node.js 22 or 24 LTS when possible.** Node.js 18 and 20 are end-of-life as of this update, as are the intervening odd-numbered releases. They no longer receive official security fixes. Older-version compatibility is a temporary fallback, not a substitute for an updated runtime. The helper prints this warning on Node 18–21 before making a live request. [Official release status](https://nodejs.org/en/about/previous-releases) · [End-of-life security implications](https://nodejs.org/en/about/eol)

1. Put this folder somewhere you can inspect it, then open a terminal in that folder.
2. Confirm the runtime and read the local help:

   ```sh
   node --version
   node workos-owner-test.mjs --help
   ```

3. Optional: run the offline tests. These generate test keys in memory and use mocked transport; they do not contact WorkOS:

   ```sh
   node workos-owner-test.test.mjs
   ```

   Direct test-file invocation also works on Node 18.0, which does not yet have the `--test` command-line flag. Node 18 may print a normal experimental test-runner warning.

4. When you want to perform the live test, run this yourself. On macOS/Linux, this also disables core dumps for this one process:

   ```sh
   (ulimit -c 0 && node workos-owner-test.mjs --run)
   ```

   On Windows, run `node workos-owner-test.mjs --run` in your private terminal, without diagnostic dumping enabled.

5. Open the exact address printed by the helper in your own browser, enter the displayed user code, and check it matches before approving. Use the owner account. **Do not paste a device code, access token, refresh token, password, or API key into chat.** The helper never displays them.
6. Let it finish. Exchange, refresh, and cleanup status lines are safe to report back. The session ID is printed specifically for targeted cleanup; it is not an access token.

Running the script with no argument or `--help` does nothing online. `--run` deliberately starts a new live authentication flow. There is no automatic browser launch, replacement login flow, background process, or recurring monitor.

## Older-Node compatibility update

The original Node 22 minimum was stricter than the built-in APIs this helper actually needs. This update accepts Node 18+, explicitly imports the monotonic clock from `node:perf_hooks`, and adds runtime/command-line regression tests. It does not add dependencies or a polyfill. JWT signature and claim verification, pinned endpoints, token secrecy, the private-terminal/debugging checks, bounded retries, and exact-session cleanup remain intact.

See `OFFLINE-TEST-RESULTS.txt` for the exact runtimes tested and results. A passing offline suite checks the helper's logic with generated test keys and mocked transport; it does not prove a real WorkOS exchange or refresh has succeeded. Windows and macOS were not separately executed in this review. Node versions below 18 are not supported.

## Expected result and limits

- The access JWT signature is verified using pinned WorkOS public signing keys. The issuer, application client ID, owner user ID, session identity, and token timestamps are checked.
- Both observed access-token lifetimes must be at most 300 seconds. This smoke test refreshes before expiration; it does not wait five minutes to test the expired-access-token path.
- The app's configured maximum session length and inactivity timeout were separately read and verified as 3,600 seconds. A short smoke test cannot empirically prove the one-hour cutoff. The server's exact new-session expiry can be checked separately using its session record.
- Cleanup makes a session-specific request to WorkOS's supported logout endpoint. It does not follow the resulting redirect and does not send browser cookies.
- An HTTP success/redirect from logout is insufficient. The helper tests the latest known refresh token afterward. It reports a session-end pass only for an unambiguous `400 invalid_grant` response while possession of the current refresh token is certain.
- A rejected refresh **does not prove immediate invalidation of already issued access JWTs**. A backend that only verifies JWT signatures can continue accepting them until expiration. The output labels the latest *observed* expiry; a lost token response may have issued a newer JWT with an unobserved expiry.
- If logout is unsupported without a browser, an app logout destination is missing, or any result is uncertain, the helper reports incomplete cleanup rather than claiming success. It never creates an API key or changes logout settings to get around that.

## If cleanup is incomplete

Report the safe status lines, test start time, and exact `Cleanup session ID` back to the assistant. The existing connected WorkOS account can revoke **that one session** through `revokeUserSession`, then read its status to verify the result. Do not use an all-sessions revoke.

If a token-exchange response was lost before a session ID was available, stop and ask for an application-specific session check using the printed app ID and test start time. Do not immediately run another login. A force-quit, power loss, or network outage can prevent cleanup; absence of tokens in memory is not proof of server-side revocation.

The helper does not ask for or read credentials. It makes no filesystem writes and emits no token logs or telemetry. WorkOS itself still processes the sign-in and may keep normal security records. JavaScript strings cannot be guaranteed to be securely erased, and a general-purpose OS may page memory or create diagnostics. Use a trusted local machine with disk protection, without recording/debugging, and let the process exit after cleanup.

## Verified configuration

- Application: AWS Permissions CLI, `app_01M4F8908SNZGNK94B9194PTQ2`
- Client: `client_01M4F8908R45SEPPWV0KN3Q7NW`
- Production environment: `environment_01M0WAF6WHJSEW95T4PTT5D2Y1`
- Access-token duration: 300 seconds
- Maximum session length / inactivity timeout: 3,600 / 3,600 seconds
- Owner user identity is pinned in the source from the verified WorkOS user record
- Device page: `https://rousing-school-60.authkit.app/device`
- Issuer: `https://api.workos.com/user_management/client_01M0WAF72P892WH9FCE0VFRGWC`
- JWKS: `https://api.workos.com/sso/jwks/client_01M0WAF72P892WH9FCE0VFRGWC`

The issuer uses the environment's default application ID while the signed `client_id` must identify AWS Permissions CLI. Both were verified through read-only WorkOS configuration/discovery on October 9. If configuration changes, re-review the pins; do not weaken verification.

## Official references

- [WorkOS CLI Auth](https://workos.com/docs/authkit/cli-auth): native public-client device exchange and refresh without a client secret
- [Applications](https://workos.com/docs/authkit/applications): application context and issuer/client-ID distinction
- [Session resilience](https://workos.com/docs/authkit/session-resilience): transient failures and the 30-second refresh replay grace period
- [Logout](https://workos.com/docs/reference/authkit/logout): session-specific logout URL
- [Session API](https://workos.com/docs/reference/authkit/session): API-key-authenticated revoke endpoint
- [Sessions](https://workos.com/docs/authkit/sessions): session and access-token lifetimes
