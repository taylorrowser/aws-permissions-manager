# Acceptance run after the dashboard redesign

Re-run on a phone after deploying the redesign (PRs #8 and #9). The V1 run and its results stay in
[v1-acceptance.md](v1-acceptance.md); this covers only what the redesign changed. Record each step as
**PASS**, **FAIL** or **NOT RUN** with the date. Never write keys, codes, session values or push endpoints here.

| # | Step | Expected | Result |
|---|---|---|---|
| 1 | iPhone: open the Home Screen app (reinstall from Safari if it was removed) | Signed in, three tabs: Requests, Projects, Settings | NOT RUN |
| 2 | Scroll and overscroll each screen; on Settings tap the key-name field so the keyboard opens | The tab bar stays at the bottom the whole time | NOT RUN |
| 3 | Settings → Turn on notifications → Allow (if not already on) | A test notification arrives; the device is listed under Notifications | NOT RUN |
| 4 | Keep Requests open; from an agent, request `s3:ListAllMyBuckets` on `*` for project `v1check` | The row appears within about 10 s without a reload; the Requests badge counts it; it shows the project, the reason and **Read-only** | NOT RUN |
| 5 | Tap the row, then Approve | The row opens with Allow / On / From and the buttons; approving removes it in place and shows the message; Projects shows `v1check` | NOT RUN |
| 6 | Request `dynamodb:*` on `*` for `v1check`, tap the row, tap Approve, then Cancel | The row is labelled **Full access** with warnings; a dialog asks first; Cancel leaves it pending. Then Reject it | NOT RUN |
| 7 | Projects → `v1check` → Revoke the grant → confirm | The grant disappears in place; the project shows no permissions | NOT RUN |
| 8 | Settings → Agent keys: create a key, then delete it | The key is shown once and copies; deleting asks first and removes it in place | NOT RUN |
| 9 | Open an old notification or visit `/devices` or `/keys` | Lands on Settings | NOT RUN |
| 10 | Settings → Sign out, then open the app again | Sign-in page; signing in returns to Requests | NOT RUN |
