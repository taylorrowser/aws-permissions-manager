"""HTML for the owner dashboard. Server-rendered; JavaScript (static/app.js) only adds
confirm prompts and push notification sign-up."""
import html
import json
import time

from . import policy

e = html.escape

STYLE = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1d1d1f;--muted:#6e6e73;--line:#d2d2d7;--card:#fff;--pend:#fff8e1;--pendline:#e0b000;--code:#f5f5f7;--ok:#1f7a3a;--no:#b3261e;--msg:#e8f1ff}
@media (prefers-color-scheme:dark){:root{--bg:#000;--fg:#f5f5f7;--muted:#98989d;--line:#3a3a3c;--card:#1c1c1e;--pend:#2b2410;--pendline:#8a6d00;--code:#2c2c2e;--msg:#10233f}}
*{box-sizing:border-box}
body{font:16px/1.45 -apple-system,system-ui,sans-serif;max-width:960px;margin:0 auto;padding:max(1rem,env(safe-area-inset-top)) 1rem 3rem;background:var(--bg);color:var(--fg)}
header{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}
h1{font-size:1.35rem;margin:.4rem 0}h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
.card{border:1px solid var(--line);background:var(--card);border-radius:12px;padding:1rem;margin:.8rem 0;overflow-wrap:anywhere}
.pending{border-color:var(--pendline);background:var(--pend)}.muted{color:var(--muted)}.msg{background:var(--msg);padding:.7rem 1rem;border-radius:10px}
code,pre{font:13px ui-monospace,Menlo,monospace}pre{background:var(--code);padding:.6rem;border-radius:8px;overflow:auto;white-space:pre-wrap}
button,.button{font:inherit;padding:.55rem 1.1rem;border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer;margin:.2rem .4rem .2rem 0;text-decoration:none;display:inline-block}
.ok{background:var(--ok);color:#fff;border-color:var(--ok)}.no{color:var(--no)}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.35rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
form{display:inline}input[type=text]{font:inherit;padding:.5rem;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg)}
.secret{font:15px ui-monospace,Menlo,monospace;padding:.7rem;background:var(--code);border-radius:8px;user-select:all;word-break:break-all}
@media (max-width:640px){table,tbody,tr,td,th{display:block}tr{border-bottom:1px solid var(--line);padding:.4rem 0}td,th{border:0;padding:.15rem 0}tr:first-child{display:none}}
"""

HEAD = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
        '<meta name="apple-mobile-web-app-capable" content="yes"><meta name="mobile-web-app-capable" content="yes">'
        '<meta name="apple-mobile-web-app-title" content="AWS Permissions">'
        '<meta name="theme-color" content="#232f3e">'
        '<link rel="manifest" href="/manifest.webmanifest"><link rel="apple-touch-icon" href="/apple-touch-icon.png">'
        '<link rel="icon" href="/icon-192.png"><title>AWS Permissions</title>'
        f'<style>{STYLE}</style><script src="/app.js" defer></script></head><body>')


def _form(fields, label, cls="", confirm=""):
    hidden = "".join(f'<input type="hidden" name="{e(k)}" value="{e(str(v))}">' for k, v in fields.items())
    data = f' data-confirm="{e(confirm)}"' if confirm else ""
    return f'<form method="post" action="/action"{data}>{hidden}<button class="{cls}">{e(label)}</button></form>'


def _when(ts):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts)) if ts else ""


def _codes(items, sep=", "):
    return sep.join(f"<code>{e(x)}</code>" for x in items)


def login_page(error=""):
    msg = f"<p class=msg>{e(error)}</p>" if error else ""
    return (HEAD + "<h1>AWS Permissions</h1>" + msg +
            "<p>Approve AWS permissions for your agents.</p>"
            '<p><a class="button ok" href="/login">Sign in</a></p></body></html>')


def error_page(text):
    return HEAD + f"<h1>AWS Permissions</h1><p class=msg>{e(text)}</p><p><a href='/'>Back</a></p></body></html>"


def dashboard(app, owner, msg="", new_key=None):
    store, broker = app.store, app.broker
    out = [HEAD, "<header><div><h1>AWS Permissions</h1>"
           f"<div class=muted>Account {e(broker.account)} · {e(owner)}</div></div>"
           '<div><a class=button href="/">Refresh</a>'
           '<form method="post" action="/logout"><button>Sign out</button></form></div></header>']
    if msg:
        out.append(f"<p class=msg>{e(msg)}</p>")
    if new_key:
        out.append(
            "<div class='card pending'><b>New API key. Copy it now; it won't be shown again.</b>"
            f"<p class=secret>{e(new_key)}</p>"
            "<p>On the agent's machine run <code>apm login --paste</code> and paste it, or set "
            "<code>APM_API_KEY</code> in the agent's environment. Agents with the plugin can instead "
            "connect themselves, which you approve here.</p></div>")

    for c in store.connects():
        out.append(
            f"<div class='card pending' id='connect-{e(c['code'])}'><b>Connect agent <code>{e(c['name'])}</code>?</b>"
            f"<div class=muted>{_when(c['created_at'])} · {e(c.get('info') or '')}</div>"
            f"<p>Code <b><code>{e(c['code'])}</code></b>. Approve only if you just started this and the agent "
            "shows the same code. It gets an API key that can request (never approve) permissions.</p><p>"
            + _form({"op": "approve_connect", "code": c["code"]}, "Approve", "ok")
            + _form({"op": "reject_connect", "code": c["code"]}, "Reject", "no") + "</p></div>")

    pending = store.list(status="pending")
    out.append(f"<h2>Pending requests ({len(pending)})</h2>")
    if not pending:
        out.append("<p class=muted>Nothing waiting.</p>")
    projects = store.projects()
    for r in pending:
        stmt = policy.statement(r["id"], r["actions"], r["resources"])
        new = "" if r["project"] in projects else f" <b>(new project: creates role {e(policy.role_name(r['project']))})</b>"
        wild = any("*" in x for x in r["actions"] + r["resources"])
        out.append(
            f"<div class='card pending' id='req-{r['id']}'><b>#{r['id']} · <code>{e(r['project'])}</code></b>{new}"
            f"<div class=muted>{_when(r['created_at'])} · from {e(r.get('requester') or 'unknown')}</div>"
            f"<p><b>Reason:</b> {e(r['reason'])}</p>"
            f"<p><b>Actions:</b> {_codes(r['actions'])}<br><b>Resources:</b> {_codes(r['resources'])}</p>"
            + ("<p class=no><b>Includes wildcards.</b> Check the scope before approving.</p>" if wild else "")
            + f"<details><summary>Policy statement</summary><pre>{e(json.dumps(stmt, indent=2))}</pre></details><p>"
            + _form({"op": "approve", "id": r["id"], "digest": r["digest"]}, "Approve", "ok")
            + _form({"op": "reject", "id": r["id"], "digest": r["digest"]}, "Reject", "no")
            + "</p></div>")

    out.append("<h2>Projects</h2><p class=muted>Grants are read live from IAM.</p>")
    if not projects:
        out.append("<p class=muted>No projects yet. Approving a request for a new project creates it.</p>")
    for project in projects:
        if not broker.in_sync(project, store.approved(project)):
            out.append(f"<div class='card pending'><b><code>{e(project)}</code>: IAM doesn't match your decisions.</b> "
                       "An IAM update may have failed or been interrupted. "
                       + _form({"op": "sync_project", "project": project}, "Re-apply decisions", "ok") + "</div>")
        grants = broker.grants(project)
        out.append(f"<div class=card><b><code>{e(project)}</code></b> · role <code>{e(policy.role_name(project))}</code>")
        if not grants or not grants["Statement"]:
            out.append("<p class=muted>No permissions granted.</p>")
        else:
            out.append("<table><tr><th>Grant</th><th>Actions</th><th>Resources</th><th>Reason</th><th></th></tr>")
            for s in grants["Statement"]:
                sid = s.get("Sid", "")
                req = store.get(int(sid[3:])) if sid.startswith("Req") and sid[3:].isdigit() else None
                out.append(
                    f"<tr><td><code>{e(sid)}</code></td><td>{_codes(_list(s.get('Action', [])), '<br>')}</td>"
                    f"<td>{_codes(_list(s.get('Resource', [])), '<br>')}</td>"
                    f"<td>{e(req['reason']) if req else '<span class=muted>unknown</span>'}</td>"
                    f"<td>{_form({'op': 'revoke', 'project': project, 'sid': sid}, 'Revoke', 'no', f'Revoke {sid} from {project}?')}</td></tr>")
            out.append("</table>")
        out.append("<p>" + _form({"op": "remove_project", "project": project}, "Delete project", "no",
                                 f"Delete role {policy.role_name(project)} and all its grants?") + "</p></div>")

    out.append("<h2>Notifications</h2><div class=card>"
               f'<p id="push-status" class=muted data-vapid="{e(app.s.vapid_public)}">Checking this device…</p>'
               '<button id="enable-push" class="ok" hidden>Enable notifications on this device</button>')
    subs = store.subscriptions()
    if subs:
        out.append("<table><tr><th>Device</th><th>Added</th><th></th></tr>")
        for s in subs:
            out.append(f"<tr><td>{e(_device(s['label']))}</td><td>{_when(s['created_at'])}</td>"
                       f"<td>{_form({'op': 'delete_device', 'pk': s['pk']}, 'Remove', 'no')}</td></tr>")
        out.append("</table><p>" + _form({"op": "test_push"}, "Send test notification") + "</p>")
    out.append("</div>")

    out.append("<h2>Agent API keys</h2><div class=card><p class=muted>Agents use a key to list projects, "
               "request permissions and get short-lived credentials. They can never approve.</p>")
    keys = store.keys()
    if keys:
        out.append("<table><tr><th>Name</th><th>Key</th><th>Created</th><th>Last used</th><th></th></tr>")
        for k in keys:
            out.append(f"<tr><td>{e(k['name'])}</td><td><code>{e(k['prefix'])}…</code></td><td>{_when(k['created_at'])}</td>"
                       f"<td>{_when(k['last_used']) or 'never'}</td>"
                       f"<td>{_form({'op': 'delete_key', 'pk': k['pk']}, 'Delete', 'no', 'Delete key ' + k['name'] + '?')}</td></tr>")
        out.append("</table>")
    out.append('<form method="post" action="/action"><input type="hidden" name="op" value="create_key">'
               '<input type="text" name="name" placeholder="name, e.g. macbook" maxlength="40" required> '
               "<button>Create key</button></form></div>")

    history = [r for r in store.list() if r["status"] != "pending"][:25]
    if history:
        out.append("<h2>Recent decisions</h2><table><tr><th>#</th><th>Project</th><th>Status</th><th>Actions</th><th>Reason</th><th>When</th></tr>")
        for r in history:
            out.append(f"<tr><td>{r['id']}</td><td><code>{e(r['project'])}</code></td><td>{e(r['status'])}</td>"
                       f"<td>{e(', '.join(r['actions']))}</td><td>{e(r['reason'])}</td><td>{_when(r['decided_at'])}</td></tr>")
        out.append("</table>")
    out.append("</body></html>")
    return "".join(out)


def _device(ua):
    for name in ("iPhone", "iPad", "Android", "Macintosh", "Windows", "Linux"):
        if name in ua:
            return {"Macintosh": "Mac"}.get(name, name) + (" (Chrome)" if "Chrome/" in ua else " (Firefox)" if "Firefox/" in ua else "")
    return ua[:40] or "device"


def _list(v):
    return v if isinstance(v, list) else [v]
