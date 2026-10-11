# Non-live integration slice, 7 October 2026

Frozen recovered simulator files remain unchanged and separately testable. New package: Python 3.12, Pydantic contracts, FastAPI REST/browser HTTP, official MCP SDK stateless Streamable HTTP; injected JWT/JWKS and AWS SDK adapters; SQLite offline command journal. No live provider clients, deployment, real keys, or production trust installation in this build.

1. Strict, shared contracts; pure read projections; durable idempotent commands and exact immutable approval manifests
2. Distinct verified human browser approval capability, origin/CSRF, one-time challenge/revision/digest checks; bearer caller can never become approver
3. Bounded existing-EC2 compiler; provider identity/trust/policy observations; credential-process-only secret delivery
4. Logical roles use new physical role revisions for changed grants. Stop predecessor issuance, drain known leases before replacement; quarantine unknown observations. Old sessions stay pinned to snapshot and absolute expiry. Temporary changes explicitly approve restoration as another new revision
5. REST, CLI, website, and stable /mcp share service authorization. Unconfigured production and enrollment deny; fixture mode explicitly opt-in
6. Fresh unit/HTTP/protocol/SDK stub tests, source hashing, independent review; rendered UI blocked by documented browser restrictions

Design constraints: no unique-machine attestation assumed; unsigned environment/thread IDs are audit labels. Live enrollment requires installed trusted provider plus standing grant. AWS STS minimum 900 seconds and session policy 2048 characters are enforced. Immediate revocation, distributed fencing, production persistence, WorkOS app setup, live IAM isolation and rendered browser QA remain gates, not claims.

References checked 2026-10-07:
- https://workos.com/docs/authkit/connect/token-claims
- https://workos.com/docs/authkit/applications
- https://workos.com/docs/authkit/cli-auth
- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
