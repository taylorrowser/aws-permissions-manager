"""HTML for the owner web app. Server-rendered; static/app.js adds confirm prompts, local times,
offline handling, install help and push notification sign-up.

Screens: Requests (/, /requests/<id>, /connect/<code>), Projects, Notifications (/devices), Keys."""
import html
import json
import time

from . import policy

e = html.escape

SERVICES = {
    "s3": "S3", "ec2": "EC2", "lambda": "Lambda", "dynamodb": "DynamoDB", "cloudfront": "CloudFront",
    "logs": "CloudWatch Logs", "cloudwatch": "CloudWatch", "sqs": "SQS", "sns": "SNS", "ecr": "ECR",
    "ecs": "ECS", "rds": "RDS", "route53": "Route 53", "acm": "Certificate Manager", "ssm": "Systems Manager",
    "secretsmanager": "Secrets Manager", "kms": "KMS", "cloudformation": "CloudFormation", "iam": "IAM",
    "sts": "STS", "apigateway": "API Gateway", "events": "EventBridge", "states": "Step Functions",
    "bedrock": "Bedrock", "athena": "Athena", "glue": "Glue", "kinesis": "Kinesis", "elasticloadbalancing": "ELB",
}

ICONS = {
    "requests": '<path d="M4 13h4l2 3h4l2-3h4M4 13V6a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v7M4 13v5a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5"/>',
    "projects": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    "devices": '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
    "keys": '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.8-9.8M16 7l3 3M19 4l2 2"/>',
}
TABS = [("/", "requests", "Requests"), ("/projects", "projects", "Projects"),
        ("/devices", "devices", "Notifications"), ("/keys", "keys", "Keys")]


def _icon(name):
    return (f'<svg class=icon viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" '
            f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{ICONS[name]}</svg>')


def _head(app, title):
    from .web import ASSET_VERSION
    v = ASSET_VERSION
    stage = "" if app.s.stage == "prod" else f"[{app.s.stage}] "
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
            '<meta name="apple-mobile-web-app-capable" content="yes"><meta name="mobile-web-app-capable" content="yes">'
            '<meta name="apple-mobile-web-app-title" content="AWS Permissions">'
            '<meta name="theme-color" content="#f6f7f9" media="(prefers-color-scheme: light)">'
            '<meta name="theme-color" content="#111418" media="(prefers-color-scheme: dark)">'
            '<meta name="color-scheme" content="light dark">'
            '<link rel="manifest" href="/manifest.webmanifest"><link rel="apple-touch-icon" href="/apple-touch-icon.png">'
            f'<link rel="icon" href="/icon-192.png"><title>{e(stage + title)} · AWS Permissions</title>'
            f'<link rel="stylesheet" href="/app.css?v={v}"><script src="/app.js?v={v}" defer></script></head>')


def _stage(app):
    return "" if app.s.stage == "prod" else f'<span class=stage title="Not production">{e(app.s.stage)}</span>'


def _flash(msg):
    if not msg:
        return ""
    cls = "flash error" if msg.startswith("Error") else "flash"
    return f'<p class="{cls}" role="status" tabindex="-1" id="flash">{e(msg)}</p>'


def layout(app, owner, active, title, body, msg="", heading=None):
    pending = len(app.store.list(status="pending")) + len(app.store.connects())
    tabs = []
    for href, key, label in TABS:
        current = ' aria-current="page"' if key == active else ""
        count = f' <span class=count aria-label="{pending} waiting">{pending}</span>' if key == "requests" and pending else ""
        tabs.append(f'<a href="{href}"{current}>{_icon(key)}<span class=label>{label}</span>{count}</a>')
    return (_head(app, title) + f'<body data-page="{e(active)}" data-pending="{pending}" '
            f'data-vapid="{e(app.s.vapid_public)}">'
            '<a class=skip href="#main">Skip to content</a>'
            '<div id=offline class=banner role=status hidden>You\'re offline. Approving and rejecting need a connection; '
            'nothing is saved for later.</div>'
            '<header class=top><a class=brand href="/"><img src="/icon-192.png" alt="" width=28 height=28>'
            f'<span>AWS Permissions</span></a>{_stage(app)}'
            '<form method=post action="/logout"><button class=link>Sign out</button></form></header>'
            f'<nav class=tabs aria-label="Sections">{"".join(tabs)}</nav>'
            f'<main id=main><h1>{e(heading or title)}</h1>{_flash(msg)}{body}</main>'
            f'<footer>AWS account {e(app.broker.account)} · {e(app.broker.region)} · signed in as {e(owner)}</footer>'
            '</body></html>')


def _form(fields, label, cls="", confirm="", back="/"):
    fields = {**fields, "back": back}
    hidden = "".join(f'<input type="hidden" name="{e(k)}" value="{e(str(v))}">' for k, v in fields.items())
    data = f' data-confirm="{e(confirm)}"' if confirm else ""
    return f'<form method="post" action="/action"{data}>{hidden}<button class="{cls}">{e(label)}</button></form>'


def _time(ts):
    if not ts:
        return ""
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
    return f'<time datetime="{iso}">{time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))}</time>'


def _codes(items):
    return "".join(f"<li><code>{e(x)}</code></li>" for x in items)


def _service(action):
    prefix = action.split(":", 1)[0]
    return SERVICES.get(prefix, prefix)


def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def login_page(app, error="", next_path="/"):
    from urllib.parse import urlencode
    href = "/login" + ("?" + urlencode({"next": next_path}) if next_path != "/" else "")
    msg = f'<p class="flash error" role="alert">{e(error)}</p>' if error else ""
    deep = ("<p class=muted>Sign in to see the request you opened.</p>"
            if next_path.startswith(("/requests/", "/connect/")) else "")
    return (_head(app, "Sign in") + '<body data-page="login" class=center><main id=main class=signin>'
            '<img src="/icon-192.png" alt="" width=72 height=72>'
            f'<h1>AWS Permissions {_stage(app)}</h1>'
            '<p>Approve the AWS access your agents ask for.</p>' + msg + deep +
            f'<p><a class="button primary wide" href="{e(href)}">Sign in</a></p>'
            '<p class=muted>Only the owner\'s verified email can sign in.</p></main></body></html>')


def error_page(app, text, back="/"):
    return (_head(app, "Problem") + '<body data-page="error" class=center><main id=main class=signin>'
            f'<h1>Something needs attention</h1><p class="flash error" role="alert">{e(text)}</p>'
            f'<p><a class="button wide" href="{e(back)}">Back to AWS Permissions</a></p></main></body></html>')


# ---------- requests ----------

def _scope_notes(r):
    notes = []
    for a in r["actions"]:
        verb = a.split(":", 1)[1]
        if verb == "*":
            notes.append(f"<code>{e(a)}</code> allows <b>every {e(_service(a))} action</b>, including deleting things.")
        elif "*" in verb or "?" in verb:
            notes.append(f"<code>{e(a)}</code> matches several {e(_service(a))} actions.")
    return notes


def request_card(app, r, projects, back="/"):
    rid, project = r["id"], r["project"]
    new = r["project"] not in projects
    notes = _scope_notes(r)
    stmt = policy.statement(rid, r["actions"], r["resources"])
    all_resources = r["resources"] == ["*"]
    on = ("<p class=on><b>On:</b> all resources in the account</p>" if all_resources else
          f'<p class=on><b>On:</b></p><ul class=codes>{_codes(r["resources"])}</ul>')
    chips = f'<span class=chip>#{rid}</span>' + ('<span class="chip new">New project</span>' if new else "")
    services = sorted({_service(a) for a in r["actions"]})
    summary = f"{_plural(len(r['actions']), 'action')} in {', '.join(services)}"
    out = [f'<article class="card request" id="req-{rid}" aria-labelledby="req-{rid}-t">'
           f'<div class=card-head><h2 id="req-{rid}-t"><a href="/requests/{rid}">{e(project)}</a></h2>{chips}</div>'
           f'<p class=meta>{e(summary)} · from {e(r.get("requester") or "unknown")} · {_time(r["created_at"])}</p>'
           f'<blockquote class=reason>{e(r["reason"])}</blockquote>'
           f'<p class=on><b>Allow:</b></p><ul class=codes>{_codes(r["actions"])}</ul>{on}']
    if new:
        out.append(f'<p class=note>Approving creates the project and its role <code>{e(policy.role_name(project))}</code>.</p>')
    for n in notes:
        out.append(f'<p class=warn>{n}</p>')
    out.append(f'<details><summary>Exact policy statement</summary><pre>{e(json.dumps(stmt, indent=2))}</pre></details>')
    if r["status"] == "pending":
        confirm = (f"Approve broad access ({', '.join(a for a in r['actions'] if '*' in a)}) for {project}?"
                   if notes else "")
        out.append('<div class=decide>'
                   + _form({"op": "approve", "id": rid, "digest": r["digest"]}, "Approve", "primary", confirm, back)
                   + _form({"op": "reject", "id": rid, "digest": r["digest"]}, "Reject", "danger", "", back)
                   + "</div>")
    out.append("</article>")
    return "".join(out)


def connect_card(c, back="/"):
    code = c["code"]
    return (f'<article class="card connect" id="connect-{e(code)}" aria-labelledby="connect-{e(code)}-t">'
            f'<div class=card-head><h2 id="connect-{e(code)}-t">Connect agent “{e(c["name"])}”?</h2>'
            '<span class="chip new">New agent</span></div>'
            f'<p class=meta>{_time(c["created_at"])} · {e(c.get("info") or "")}</p>'
            f'<p class=code-check>Code <b class=code>{e(code)}</b></p>'
            '<p>Approve only if you just started this and the agent shows the same code. The agent gets an API key '
            'that can ask for permissions but never approve them.</p><div class=decide>'
            + _form({"op": "approve_connect", "code": code}, "Approve", "primary", "", back)
            + _form({"op": "reject_connect", "code": code}, "Reject", "danger", "", back) + "</div></article>")


def _status_chip(status):
    return f'<span class="chip s-{e(status)}">{e(status.capitalize())}</span>'


def requests_page(app, owner, msg=""):
    store = app.store
    pending, connects, projects = store.list(status="pending"), store.connects(), store.projects()
    out = ['<p class="nudge" id="push-nudge" hidden><a href="/devices">Turn on notifications</a> on this device '
           'to hear about new requests.</p>']
    for c in connects:
        out.append(connect_card(c))
    for r in pending:
        out.append(request_card(app, r, projects))
    if not pending and not connects:
        out.append('<div class=empty><p><b>Nothing to review.</b></p><p class=muted>When an agent asks for AWS access, '
                   'it shows up here and you get a notification.</p></div>')
    history = [r for r in store.list() if r["status"] != "pending"][:10]
    if history:
        out.append('<h2 class=section>Recent decisions</h2><ul class=list>')
        for r in history:
            out.append(f'<li class=link-row><a href="/requests/{r["id"]}"><span><b>{e(r["project"])}</b> <span class=muted>#{r["id"]}</span>'
                       f'<br><span class=muted>{e(", ".join(r["actions"]))}</span></span>'
                       f'<span class=right>{_status_chip(r["status"])}<br>{_time(r["decided_at"])}</span></a></li>')
        out.append("</ul>")
    n = len(pending) + len(connects)
    heading = f"Requests ({n})" if n else "Requests"
    return layout(app, owner, "requests", "Requests", "".join(out), msg, heading)


def request_page(app, owner, r, msg=""):
    rid = r["id"]
    body = []
    if r["status"] != "pending":
        when = _time(r["decided_at"])
        body.append(f'<p class="flash">This request was {_status_chip(r["status"])} {when}.'
                    + (f' Note: {e(r["note"])}' if r.get("note") else "")
                    + (' See it in <a href="/projects">Projects</a>.' if r["status"] == "approved" else "") + "</p>")
    body.append(request_card(app, r, app.store.projects(), back=f"/requests/{rid}"))
    body.append('<p><a href="/">← All requests</a></p>')
    return layout(app, owner, "requests", f"Request #{rid}", "".join(body), msg)


def connect_page(app, owner, code, msg=""):
    match = [c for c in app.store.connects() if c["code"] == code]
    if match:
        body = connect_card(match[0], back=f"/connect/{code}")
    else:
        body = ('<div class=empty><p><b>This connect request is no longer waiting.</b></p><p class=muted>It was '
                'approved, rejected or expired (they last 15 minutes). If the agent still needs access, start '
                'connecting again from the agent.</p></div>')
    return layout(app, owner, "requests", "Connect an agent", body + '<p><a href="/">← All requests</a></p>', msg)


# ---------- projects ----------

def projects_page(app, owner, msg=""):
    store, broker = app.store, app.broker
    projects = store.projects()
    out = ['<p class=muted>Each project is an IAM role agents can use. Grants are read live from IAM.</p>']
    if not projects:
        out.append('<div class=empty><p><b>No projects yet.</b></p><p class=muted>A project is created the first '
                   'time you approve a request for it.</p></div>')
    for project in projects:
        if not broker.in_sync(project, store.approved(project)):
            out.append(f'<div class="warn" role="alert"><p><b>{e(project)}: IAM doesn\'t match your decisions.</b> An IAM '
                       'update failed or was interrupted, so the grants below may differ from what you approved or '
                       'revoked.</p>' + _form({"op": "sync_project", "project": project}, "Re-apply decisions",
                                              "primary", "", "/projects") + "</div>")
        grants = broker.grants(project)
        statements = grants["Statement"] if grants else []
        out.append(f'<article class=card id="project-{e(project)}"><div class=card-head><h2>{e(project)}</h2>'
                   f'<span class=chip>{_plural(len(statements), "grant")}</span></div>'
                   f'<p class=meta>Role <code>{e(policy.role_name(project))}</code> · agents use profile '
                   f'<code>apm-{e(project)}</code></p>')
        if not statements:
            out.append("<p class=muted>No permissions granted. Agents can't use this project until you approve a request.</p>")
        else:
            out.append("<ul class=grants>")
            for s in statements:
                sid = s.get("Sid", "")
                req = store.get(int(sid[3:])) if sid.startswith("Req") and sid[3:].isdigit() else None
                resources = _list(s.get("Resource", []))
                on = "all resources" if resources == ["*"] else ""
                out.append(
                    f'<li><div><ul class=codes>{_codes(_list(s.get("Action", [])))}</ul>'
                    + (f'<p class=on>On {on}</p>' if on else f'<p class=on>On:</p><ul class=codes>{_codes(resources)}</ul>')
                    + (f'<p class=muted>{e(req["reason"])} · <a href="/requests/{req["id"]}">#{req["id"]}</a></p>' if req
                       else f'<p class=muted>Grant <code>{e(sid)}</code></p>')
                    + "</div>"
                    + _form({"op": "revoke", "project": project, "sid": sid}, "Revoke", "danger small",
                            f"Revoke this grant from {project}? Agents lose it within minutes.", "/projects")
                    + "</li>")
            out.append("</ul>")
        out.append('<details class=danger-zone><summary>Delete project…</summary>'
                   f'<p>Deletes role <code>{e(policy.role_name(project))}</code> and all its grants. Agents using it '
                   'lose access when their current credentials expire (within an hour).</p>'
                   + _form({"op": "remove_project", "project": project}, f"Delete {project}", "danger",
                           f"Delete project {project} and all its grants?", "/projects")
                   + "</details></article>")
    return layout(app, owner, "projects", "Projects", "".join(out), msg)


# ---------- notifications ----------

def _device(ua):
    for name in ("iPhone", "iPad", "Android", "Macintosh", "Windows", "Linux"):
        if name in ua:
            browser = (" · Edge" if "Edg/" in ua else " · Chrome" if "Chrome/" in ua or "CriOS/" in ua
                       else " · Firefox" if "Firefox/" in ua or "FxiOS/" in ua else " · Safari" if "Safari/" in ua else "")
            return {"Macintosh": "Mac"}.get(name, name) + browser
    return ua[:40] or "device"


def _health(s):
    ok, bad = s.get("last_ok_at", 0), s.get("last_error_at", 0)
    if s.get("failures"):  # reset by the next success
        status = s.get("last_status") or "no response"
        return f'<span class=warn-text>Last notification failed (HTTP {e(str(status))}) {_time(bad)}</span>'
    if ok:
        return f"Last notified {_time(ok)}"
    return "No notifications sent yet"


def devices_page(app, owner, msg=""):
    subs = app.store.subscriptions()
    out = ['<section class=card id=this-device aria-labelledby=this-device-t>'
           '<h2 id=this-device-t>This device</h2>'
           '<p id=push-status aria-live=polite>Checking notifications…</p>'
           '<div class=decide>'
           '<button id=push-enable class=primary hidden>Turn on notifications</button>'
           '<button id=push-test hidden>Send a test</button>'
           '<button id=push-disable class=danger hidden>Turn off</button>'
           '<button id=install-app hidden>Install app</button></div>'
           '<div id=install-ios class=steps hidden><p><b>On iPhone and iPad, notifications only work from the '
           'Home Screen app.</b></p><ol><li>Tap <b>Share</b> <span aria-hidden=true>(□↑)</span> in Safari.</li>'
           '<li>Choose <b>Add to Home Screen</b>, then <b>Add</b>.</li>'
           '<li>Open <b>AWS Permissions</b> from your Home Screen and come back to this page.</li></ol>'
           '<p class=muted>Needs iOS or iPadOS 16.4 or later.</p></div>'
           '<div id=push-denied class=steps hidden><p id=push-denied-help></p></div>'
           '</section>']
    out.append(f'<h2 class=section>All devices ({len(subs)})</h2>')
    if not subs:
        out.append('<p class=muted>No devices get notifications yet. Turn them on above on each phone or computer '
                   'you want alerted.</p>')
    else:
        out.append('<ul class="list devices">')
        for s in subs:
            out.append(f'<li data-device="{e(s["pk"])}"><span><b>{e(_device(s["label"]))}</b>'
                       '<span class="chip this" hidden>This device</span>'
                       f'<br><span class=muted>Added {_time(s["created_at"])}</span><br><span class=muted>{_health(s)}</span></span>'
                       + _form({"op": "delete_device", "pk": s["pk"]}, "Remove", "danger small",
                               "Stop notifications to this device?", "/devices") + "</li>")
        out.append("</ul>")
    out.append('<details class=info><summary>What notifications show</summary><p>A notification says only which '
               'project is asking and the request number, so nothing sensitive appears on a lock screen. Tapping it '
               'opens the request; you may need to sign in first. Nothing is approved from a notification.</p>'
               '<p>Devices that the browser has unsubscribed are removed automatically the next time a notification '
               'is sent. A device that keeps failing shows the error above.</p></details>')
    return layout(app, owner, "devices", "Notifications", "".join(out), msg)


# ---------- keys ----------

def keys_page(app, owner, msg="", new_key=None):
    out = []
    if new_key:
        out.append('<section class="card new-key" aria-labelledby=new-key-t><h2 id=new-key-t>Copy your new key now</h2>'
                   "<p>It won't be shown again.</p>"
                   f'<p class=secret id=secret>{e(new_key)}</p><p><button id=copy-key data-target=secret>Copy key</button></p>'
                   "<p>On the agent's machine run <code>apm login --paste</code> and paste it, or set "
                   "<code>APM_API_KEY</code> in the agent's environment.</p></section>")
    out.append('<p class=muted>Agents use a key to list projects, ask for permissions and get short-lived '
               'credentials. A key can never approve anything. Agents with the plugin can also connect themselves; '
               'you approve those on the Requests screen.</p>')
    keys = app.store.keys()
    if keys:
        out.append('<ul class=list>')
        for k in keys:
            out.append(f'<li><span><b>{e(k["name"])}</b> <code>{e(k["prefix"])}…</code><br>'
                       f'<span class=muted>Created {_time(k["created_at"])} · last used '
                       f'{_time(k["last_used"]) or "never"}</span></span>'
                       + _form({"op": "delete_key", "pk": k["pk"]}, "Delete", "danger small",
                               f"Delete key {k['name']}? Agents using it stop working.", "/keys") + "</li>")
        out.append("</ul>")
    else:
        out.append('<div class=empty><p><b>No keys yet.</b></p></div>')
    out.append('<form method="post" action="/action" class=create><input type="hidden" name="op" value="create_key">'
               '<input type="hidden" name="back" value="/keys">'
               '<label for=key-name>New key name</label><div class=row>'
               '<input type="text" id=key-name name="name" placeholder="e.g. macbook" maxlength="40" required '
               'autocomplete=off autocapitalize=off>'
               '<button class=primary>Create key</button></div></form>')
    return layout(app, owner, "keys", "Agent API keys", "".join(out), msg)


def _list(v):
    return v if isinstance(v, list) else [v]
