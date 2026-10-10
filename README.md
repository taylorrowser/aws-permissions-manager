# AWS Permissions Manager

A broker that lets agents request scoped IAM roles, lets a human approve or reject the exact change on a website, and then vends short-lived AWS credentials for the approved scope. Website, MCP, CLI and API share the same authorization model. WorkOS provides identity.

The first live use case is managing existing EC2 instances (describe, start, stop and reboot only).

## Status

This repo was set up on 10 October 2026 from the handoff package. Nothing is deployed. Live AWS enforcement and the end-to-end WorkOS token flow have not been verified. The infrastructure scaffold deliberately fails deployment.

The three source trees below are **separate checkpoints and have not been merged yet**. Merging them is Milestone 1 in the handoff guide.

## Layout

| Path | What it is |
| --- | --- |
| `broker/` | Full offline integration checkpoint (7 Oct). **This is the baseline.** Start with `broker/INTEGRATION-README.md`. The `integration/` package is current. The root `broker.py`, `server.py`, `dashboard.html` and `evidence/` are the older simulator, kept for history. |
| `auth-subset/` | Later WorkOS auth-only change set (7 Oct). Start with `auth-subset/reviewed-auth-smoke/integration/WORKOS.md`. It has not been merged into `broker/` or retested with it. |
| `owner-helper/` | Standalone Node WorkOS login diagnostic for the owner. Start with `owner-helper/README.md`. |
| `evidence/` | Test logs, manifests and independent reviews for each checkpoint. |
| `handoff/` | The original handoff guide (PDF/DOCX) and the five unchanged source archives with `SHA256SUMS.txt`, kept for provenance. |

## Getting started

Read `handoff/AWS_Permissions_Manager_Handoff.pdf` first. Section 8 covers the milestones and section 9 has the starting commands.

Offline broker tests (Python 3.12, from `broker/`):

```sh
python -m venv .venv && source .venv/bin/activate
pip install -r integration/requirements.txt boto3
python -m unittest discover -s tests -v
```

Four SDK tests skip without `boto3`. Acceptance requires zero skips.

Owner helper offline tests (Node 18+, from `owner-helper/`):

```sh
node workos-owner-test.test.mjs
```

## Safety

- Never commit or paste real tokens, device secrets, API keys or AWS credentials.
- Never run a real `credential_process` command where an assistant can see the output.
- `node workos-owner-test.mjs --run` starts a live login. Run it only in the owner's own private terminal.
- Live access, deployment and IAM changes need owner authorization first (see the handoff guide).
