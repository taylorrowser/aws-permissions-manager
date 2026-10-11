# Permission broker: rebuilt candidate, 7 October 2026

**Synthetic local simulation only. Not a production security boundary.** No AWS or WorkOS calls, cloud credentials, live IAM changes, deployment, repository publication, or paid resources. Public demo identity strings are selectable fixtures, not authentication.

This is a **new rebuilt candidate**, not recovered v2.1. It starts from the October 1 `permission-broker.zip` Library archive. The original ZIP, untouched extracted baseline, SHA-256 inventory and fresh baseline results are retained in the checkpoint. Later corrected source bytes could not be recovered; five recorded correction areas were reconstructed and tested anew.

Original archive: 155,359 bytes; SHA-256 `dcafe8e09814f17451a8823cbb1ba048d873c45e99118e6c523880868588e9ed`. Original baseline independently rerun during this build: 22 tests passed. New regression-first run: 15 cases, 5 assertion failures, 9 errors, 1 passing disjoint-grant control. Current test totals and independent review are recorded in the accompanying fresh evidence, not inferred from historical counts.

## Run locally

Python 3.10+; standard library only for server, executor, tests and demo.

```sh
cd <extracted-candidate-directory>
python3 run_tests.py
python3 demo.py
python3 server.py --db demo.sqlite3 --port 8765
```

Open `http://127.0.0.1:8765` on that same computer. Server binds loopback and rejects foreign Host/Origin values. Do not enter real secrets or operational data.

1. As Agent, submit an exact synthetic role bundle and reason.
2. As Owner Alice, inspect and approve the frozen manifest digest. This causes no provider writes.
3. In a separate terminal run `python3 executor.py --db demo.sqlite3 REQUEST_ID`. The website has no execution endpoint.
4. Refresh. Active approved bundles can vend fake session handles for either explicitly approved role, including cross-environment use.
5. Owner controls stop issuance, simulate effective revocation, or cancel a grant. Cancellation is terminal for execution and issuance. Cancellation of an active grant also denies its existing sessions in this simulator. Stopped-issuance intent survives drift quarantine and reconciliation; recovery never silently restores issuance.

### Lost acknowledgements and recovery

Run an approved executor command with `--simulate-timeout-after-write` to commit one fake policy write and lose acknowledgement. State becomes `reconciling`, with durable role claims retained.

The next executor invocation **only reads provider state**. Alternatively, use the owner's “Reconcile provider state (read-only)” button. No fake policy write occurs during reconciliation.

- All roles at desired policy: reconciliation can finalize an active receipt if still valid and uncancelled
- Some roles at approved baseline and others at desired policy: state becomes `ready_to_resume`; a **separate subsequent executor invocation** applies the remaining writes
- Unknown policy or RoleId, or a completed grant regressing to its old baseline: state requires review and remains quarantined; it is never overwritten
- Expired or cancelled: recovery remains available, but reconciliation never activates the grant and later apply is denied

The dashboard derives recovery controls independently of displayed expiry. Cancel then reconcile also performs zero fake provider writes. Reconciliation records observations and local bookkeeping; “read-only” refers to the provider, not the local journal.

### Per-role reservations and migration

Before any write intent, all role baselines and conflicts are validated atomically in one `BEGIN IMMEDIATE` transaction. A new attempt claims its entire bundle; another grant cannot overwrite any claimed role. Disjoint grants coexist. Approval alone or an overlap-blocked invocation creates no claim.

SQLite stores `(role, request_id)` claims. New acquisition is exclusive; composite keys deliberately preserve conflicting legacy claims instead of silently discarding a quarantine. Any competing claim blocks new execution. The simulated shared transaction is not a distributed IAM lock.

Migration requires durable write-attempt evidence: applying/timeout/active journal events or a receipt. State labels and old reservation rows alone do not qualify. Phantom rows with no attempt evidence are removed. Legacy unknown attempts without reservation rows regain quarantine, including past cutoff. Known revoked/cancelled attempts retain claims until cutoff. Before the first cutoff release, current provider state must still be known; late-observed drift is quarantined. Durable release evidence prevents an old grant from reclaiming roles after a legitimate successor changes them. Uncertain claims are not released just because a timer expires. Release does not change old grant/session authorization, and old sessions cannot revive.

Drift discovered in an active grant becomes visible as `needs_review`, with issuance and use denied. An unattempted baseline drift still permits a genuinely new reviewed request. A request with uncertain write evidence cannot be bypassed that way.

## Verification

`python3 run_tests.py` produces sanitized `evidence/test-results.json`. Fresh acceptance covers frozen revision/digest, audience and stable synthetic RoleIds, approved cross-environment bundle selection, owner/self/forged-owner denials, wildcard and out-of-bundle denial, 100 duplicate deliveries with one logical effect, concurrent replay, timeout/restart reconciliation, policy/RoleId drift, exact synthetic cutoff without cleanup, issuance-stop versus simulated revocation, and credential-free journal/output.

`python3 demo.py` produces a deterministic temporary-database walkthrough without session handles in saved evidence. `tests/test_rebuild_regressions.py` holds reconstruction regressions; `tests/test_recovery_http.py` tests the dashboard recovery API, including expired cancellation and repeat reconciliation with zero additional provider writes.

Optional `python3 browser_smoke.py` requires Playwright and Chromium. The fresh standalone browser attempt in this executor could not initialize Chromium's local process socket, including an admitted escalated launch; historical screenshots are not fresh verification. The supported existing cloud browser was also tried with project authorization and rejected loopback navigation with `net::ERR_BLOCKED_BY_CLIENT`. Rendered verification is therefore blocked. No alternate host was exposed, and no browser route was retried around the denial. `python3 browser_recovery.py` retains automated recovery scenarios for a supported future local runtime; they have not run here.

For reproducible recovery UI fixtures, run one at a time:

```sh
python3 qa_fixture_server.py expired-direct --port 8766
python3 qa_fixture_server.py expired-cancel --port 8767
python3 qa_fixture_server.py unknown --port 8768
python3 qa_fixture_server.py approved-cancel --port 8769
```

Select Owner Alice in each browser. First: reconcile an expired uncertain request. Second: cancel then reconcile. Third: reconcile unknown state, cancel, then reconcile again; quarantine remains. Fourth: cancel an approved request before execution. Each server uses a temporary SQLite file and removes it on normal exit. The fixture server exposes no extra API controls.

## Deliberate limits and next integration gaps

- Same OS user and writable SQLite mean no privilege isolation. Anyone with storage/code access can forge decisions, disable triggers or edit catalog state. Browser fixture identities do not implement human-only authentication
- Fake provider writes and local state commit together. This does not prove remote IAM crash safety, eventual consistency, distributed reservations or fencing
- Policies use symbolic `sim://` resources and `inventory:read`; they are not deployable AWS policies. No real EC2 operation is implemented
- Simulated revocation is an application check, not evidence that real AWS sessions are revoked. Fake session lifetime truncation does not prove provider minimum-duration or absolute-cutoff correctness
- No cleanup scheduler, rollback executor, production audit retention, rate limiting, external observability, or policy isolation
- Website: local fixture dashboard only. API: synthetic request/decision/control/reconcile/session. CLI: executor only. No MCP, reusable production SDK, WorkOS adapter or hosting definitions in this correction slice
- Future WorkOS scopes are separate from app-owned AWS grant entitlements. Future actor validation must bind exact issuer, observed audience, client ID, owner/org and actor class. Human approval requires a distinct browser-only session and exact app-client binding; same-owner CLI/MCP bearer tokens must not approve
- Future EC2 policy candidates may describe existing instances, then start/stop/reboot exact approved instance ARNs. No create/terminate, IAM/PassRole, networking or SSM execution is authorized here
- Fresh ephemeral-computer enrollment remains an unresolved root-of-trust design. No unique machine attestation or approved shared bootstrap is assumed or implemented

Do not deploy this artifact or connect live credentials. Live account facts, authenticators, approval-bound policy packet and separate authorization are still required.
