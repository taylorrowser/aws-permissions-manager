# Permissions broker: non-live integration slice

**Not deployable or a verified production security boundary. No live AWS or WorkOS calls, keys, settings, trust installation, repository publication or hosting changes occurred.** Existing root broker/server/dashboard are the frozen recovered synthetic simulator. Run the new integration package separately; it does not wrap the simulator's mutating status methods.

## What runs offline

- One strict Pydantic domain contract and service for website, REST, official MCP SDK Streamable HTTP `/mcp`, and CLI
- Frozen request revisions, exact reason/policy/ARN/digest approval; same-owner bearer tokens cannot approve
- Separate browser code-exchange/PKCE and opaque-session boundary; origin/CSRF and one-use exact-request challenge, replay denial
- Pure request/grant/operation queries. Commands alone mutate grants, reservations and journal
- App-owned owner/subject/client/role entitlements independent of WorkOS scopes; exact WorkOS signature/issuer/audience/client/org contracts, explicit no-organization mode
- Named logical roles with immutable physical AWS-role revisions, drain-before-switch, unknown-state quarantine and approved restoration for temporary changes
- Deterministic existing-EC2 compiler and injected IAM/STS SDK adapters, tested without network. No provider client factory or implicit metadata credential discovery
- Experimental key-bound coordinator enrollment under explicit standing trust; default disabled. Public JWK/challenge in MCP, signed worker proofs on direct HTTP
- CLI login/logout/status/request/revise/grants/enroll/lease and dedicated credential_process delivery, with default unconfigured live device-auth provider

## Reproduce

Python 3.12. Install official dependencies from `integration/requirements.txt` in an isolated environment. The source was checked using the exact versions recorded there. The installed boto3/botocore test dependencies in this build are at `/tmp/permission-broker-sdk`; that temporary path is not included or required after a normal requirements install.

```
python -m unittest discover -s tests -v
python -m integration.serve --offline-fixture --db /tmp/permissions-offline.sqlite3 --port 8877
python -m integration.cli --origin http://127.0.0.1:8877 --offline-fixture login
python -m integration.cli --origin http://127.0.0.1:8877 --offline-fixture --json status
```

Explicit fixture login uses public marker `OFFLINE-ONLY`, and the website offers a visibly labelled owner fixture. There is no fixture override/header in normal configuration. Browser fixture authentication is not human identity proof. Local launcher binds loopback and disables access logging. `/health` discloses non-live status. No executor route is exposed; offline tests call the internal executor command directly. This is intentional: request runtime must never acquire IAM write authority.

`python -m integration.cli --help` shows all commands. Request/lease/enrollment payload files follow the same Pydantic schemas exposed through OpenAPI and MCP. Idempotency keys are caller-scoped and reject changed payloads. Lost credential replies are not cached as secret bodies: use a fresh authenticated request, accepting another bounded issuance, or await previous lease expiry. Ordinary status never returns credentials.

## AWS semantics and scope

Only DescribeInstances and DescribeInstanceStatus (regional inventory, necessarily Resource `*`) and StartInstances/StopInstances/RebootInstances on explicit configured existing-instance ARNs. Administrator inventory is a ceiling, not worker input. No RunInstances, TerminateInstances, IAM/PassRole, instance profile/user-data/network/security changes, SSM, password or console-output access. Resource tags are administrator-only.

A logical role is reusable, but changes produce a different physical ARN, displayed in the approval manifest and website. No external existing IAM role is adopted, cloned or taken over. In-place updates of an independently existing EC2 role remain unsupported. Approval immediately stops predecessor issuance; activation waits for its known credential reservations/leases to drain. This bounds ongoing-grant changes without expiring the ongoing grant itself. Unknown execution outcomes retain the logical-role reservation and require explicit provider observation; queries never reconcile.

Temporary requests have exact start/end, and existing ongoing scope restoration is frozen in the same human-approved manifest as a separate new physical role. Unsafe/missed temporary starts are rejected. A real timely scheduler is not installed; late restoration can safely delay regained privileges and must be surfaced operationally. Stopping new issuance does not revoke existing STS credentials. An emergency provider deny/revoke procedure would need separate approval and evidence.

STS minimum duration is 900 seconds, role chaining ceiling is 3600 seconds, and session JSON is limited to 2048 characters. Prepared credential-use handles reserve up to 960 seconds (60-second redemption plus 900-second session). The immutable per-session policy has its own absolute deny cutoff; future grants cannot widen or revive old sessions. The IAM adapter re-observes the pinned RoleId, ARN, trust, boundary document/version, inline and attached policy documents before vending. Readback is not proof of global propagation or distributed fencing.

## Secrets and authentication

Real WorkOS IDs, owner, origin, JWKS and client contracts are deployment configuration only. `integration/config.review.json` is intentionally unconfigured. Browser AuthKit session tokens and Connect tokens are different verified profiles: Connect has audience; the documented session profile may omit audience, with exact app client still required. Multiple apps can share issuer. M2M uses environment audience and exact client identity; no claim scope alone grants AWS access.

Production browser persistence and production execution/store fencing deliberately refuse activation. Real WorkOS code/device exchange, JWKS acquisition/rotation, refresh/revoke integration and secure host secret storage are adapter prerequisites, not simulated successes. Offline sessions are in-memory and restart invalidates them. Browser callbacks do not convert arbitrary bearer identities into approval sessions.

AWS credential bodies only go through dedicated direct HTTP credential-process endpoints and the CLI's dedicated stdout. MCP returns non-secret handles/public enrollment metadata only. The CLI refuses TTY output as accidental-terminal protection. **A non-TTY pipe/agent-visible exec capture can still expose credential JSON.** Therefore never invoke credential-process as a model-visible command. Configure it as the private AWS SDK/CLI consumer subprocess, and expose only the requested operation result. The offline consumer test captures synthetic credentials internally and reports only a harmless operation summary. Local code under the same OS identity can still read its own process/storage; this is hygiene, not process isolation. Disable body/token/proxy/access logging on credential and auth routes before deployment.

## Coordinator enrollment delta

`integration/infrastructure/coordinator-enrollment-design.json` is the parent review-only design contract. The implemented slice uses maintained ES256/JWK/JWT primitives and RFC 7638 thumbprints. It is an **experimental DPoP-shaped application proof profile**, not full RFC 9449 OAuth DPoP compliance: no workload bearer token is issued, so no `cnf`/`ath` token binding is claimed. Each request instead requires the configured run's key, exact method/URL/body digest, server nonce, run/enrollment ID, fresh proof ID/time and current grant binding. Replay and one-use redemption are SQLite transactions. The trusted coordinator client/connection authenticates authorization; a public key/label is not unique-machine/provider attestation. A copied private key can impersonate that run until revoke/expiry.

Preparation is a mutating MCP tool. Existing user/client/platform prompts cannot be bypassed or predicted. Live ChatGPT and Claude connection, CIMD/DCR behavior, prompt behavior, refresh/reconnect, worker handoff and end-to-end private credential consumption have NOT run. Standing trust, concurrent-run/issuance production quotas, per-run delivery/storage, durable distributed nonce/session stores, and approval of the initial connection remain deployment gates. No shared environment bootstrap secret was invented or installed.

## Evidence and limits

Root `evidence/` is inherited historical synthetic evidence, not integration verification. Fresh integration checks, source hashes and independent review live in the accompanying integration evidence bundle. Full core tests are rerun against copied source; earlier totals are not proof of this package.

Rendered website QA remains **not run**: approved Chromium initialization failed at a process-singleton socket and supported browser loopback returned ERR_BLOCKED_BY_CLIENT. No browser route was retried, server exposed publicly, or settings weakened. Unit/HTTP/protocol tests validate form contents and interrupted/replayed request paths; they do not validate visual rendering.

Infrastructure under `integration/infrastructure/` is review-only and deliberately fails deployment. Separate request, human-decision, permission-executor and assume-only-vendor authority is a proposed isolation boundary, not enforced by this one-process offline SQLite implementation. Real deployment, provider isolation, trust-policy evaluation, AWS eventual consistency, IAM quotas/cleanup, WorkOS account changes, real credentials and costs all require separate review/authorization.

## Review hardening

Human exact-revision cancellation is available before any durable provider write intent. It releases only unattempted reservations and leaves predecessor issuance stopped, allowing a fresh human-approved request. Started/unknown writes cannot be cancelled away. Explicitly stopping a temporary grant cancels automatic restoration; a stop during restoration execution quarantines that attempt instead of activating new issuance. Terminal successful state cannot be rewritten by stale failure receipts.

The AWS vending bridge requires a separate `PinnedRevision` executor receipt bound to grant ID, approved manifest digest, observed RoleId and immutable role-snapshot fingerprint. Planned account/name/ARN must match before any IAM/STS call. AWS-generated RoleId does not exist when a new role is first approved; trusted executor readback pins it afterward. Production receipt authenticity, isolated storage and writer authority remain deployment gates. The assume adapter still detects delete/recreate or policy drift against that captured RoleId.

MCP tool-validation and unknown-tool errors are sanitized without echoing rejected inputs. HTTP ingress stops reading after the configured body cap rather than buffering an unlimited chunked request. Bounded coordinator renewal is synchronized only from freshly verified run authority inside the same offline transaction.

AWS-facing temporary request windows and coordinator enrollment inputs require at least 960 seconds, accounting for the 900-second STS minimum plus the 60-second redemption allowance. Reaching approval/enrollment later does not reset an absolute cutoff; issuance rechecks the remaining lifetime and can still deny. The lower-level generic proof-only enrollment adapter permits shorter lifetimes for non-AWS proof tests; those are not promises of usable AWS access.
