# Permissions broker integration evidence

## Scope

Non-live integration-ready source copy on the explicitly authorized current dot cloud computer. No AWS or WorkOS writes, credentials, trust installation, deployment, repository publication, payments or external communication. All 18 non-pycache recovered-candidate files remain byte-identical. Frozen broker.py SHA-256: 6bead7102e10ac184242db5f26b7d532a7acb1862249b31830782148a77ae14c.

Initial durable checkpoint: Library libfile_62b4e89b0c4c819198323c36aa3c4ac5, version 0. Prior recovered source/evidence remain separate items; this integration source is a new deliverable.

## Final candidate checks

Source fingerprint: 7309575ce920e9f344dfe624b4201d4fd7ee816e0473fde8c1f8d58ea08ef8ad. Full per-file SHA-256 map is in review-v4-source-manifest.json.

- Full exact-candidate unittest run: 177 passed, zero failed, zero skipped
- 42 recovered-core tests rerun; 135 integration tests
- 4 genuine boto3/botocore Stubber cases with blocked network transport and explicit synthetic credentials
- WorkOS auth: 31 cases; coordinator proof/enrollment: 23 cases
- Browser/REST/MCP protocol: 7 cases; direct coordinator HTTP: 4 cases
- CLI/private consumer: 8 cases; service transitions: 14 cases
- AWS compiler/adapters/infrastructure: 31 cases; review regression cases: 17
- Integration compileall: passed
- Sanitized offline private-consumer walkthrough: passed; no credential body emitted in evidence

Command: from candidate, PYTHONPATH=/tmp/permission-broker-sdk:. python3 -m unittest discover -s tests -v. Normal fresh environments install integration/requirements.txt rather than using that build-local SDK path. full-final-candidate.log and offline-demo-final.json contain the final local results. Earlier logs/checkpoints preserve the review and correction history and must not be confused with the final source.

## Independent review

A separate reviewer inspected exact source and added independent adversarial probes. The first review identified input-error echo paths, stopped-temporary restoration, stale operation status/receipts, bounded renewal synchronization, missed-start liveness, streamed body-size handling, exact pinned physical-role binding, name-length bounds and AWS-use minimum-lifetime admission. Corrections and 17 regression cases were added. Final independent assessment accepted this exact fingerprint as a non-live checkpoint only: 177 repository tests and 17 external controls passed with no remaining blocking scoped issue. See independent-review/FINAL-REVIEW.md and final-review.json.

## Hard limits and unverified gates

Rendered browser UI is unverified. The already authorized Chromium path failed initializing a process-singleton socket and the supported browser rejected loopback with ERR_BLOCKED_BY_CLIENT; neither route was retried and no server was exposed publicly. HTTP form/protocol tests are not visual browser verification.

All real WorkOS code/device exchange, refresh/revocation/JWKS rotation, provider IAM/STS isolation/propagation, production storage and distributed fencing, authentic executor receipt storage, live scheduler/cleanup, production run quotas, ChatGPT/Claude connection/CIMD/DCR/write-tool prompts and worker handoff remain unverified. Browser and provider production paths deliberately fail closed. IAM definitions have an impossible deployment assertion and placeholders; they are review-only.

The coordinator mechanism demonstrates authorization plus private-key possession, not unique-machine attestation. It is an experimental signed-proof application profile using maintained crypto libraries, not complete OAuth DPoP compliance. No workload bearer token is issued. MCP carries public keys, challenges and authority summaries only. Direct credential_process data must be consumed privately by an AWS SDK/CLI; non-TTY output can still be captured by an agent-visible command, so TTY refusal alone is not transcript isolation.

Inherited candidate/evidence files are historical synthetic provenance only. Current release proofs live in this integration evidence archive.
