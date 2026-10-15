"""HTML for the owner web app. Server-rendered; static/app.js adds live refresh, in-page submits,
confirm dialogs, local times, offline handling, install help and push notification sign-up.

Screens: Requests (/, /requests/<id>, /connect/<code>), Projects (/projects) and Settings
(/settings: notifications, agent keys, account). Every list leads with what matters on a phone:
project, reason and how risky the request is; details open in place."""
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
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3h.1a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8v.1a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
}
TABS = [("/", "requests", "Requests"), ("/projects", "projects", "Projects"), ("/settings", "settings", "Settings")]

READ_VERBS = ("Get", "List", "Describe", "Head", "Lookup", "Search", "Query", "Scan", "Select", "View", "Check", "BatchGet")


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
            # black-translucent: the page runs under the status bar and env(safe-area-inset-top) is real.
            # iOS 26 draws a blur about 40pt below the status bar; the stylesheet keeps text out of it.
            '<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">'
            '<meta name="theme-color" content="#f2f3f5" media="(prefers-color-scheme: light)">'
            '<meta name="theme-color" content="#0f141b" media="(prefers-color-scheme: dark)">'
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


def state(app):
    """Call first in every page: (fingerprint, pending count) read before the body, so anything
    that changes while rendering shows up on the next poll (see web.state_version)."""
    from .web import state_version
    return state_version(app.store)


def layout(app, owner, active, title, body, state, msg="", heading=None, back=None):
    """The app shell. The body never scrolls: only <main> does, so the tab bar stays put on iOS
    (no position:fixed, no viewport units). Elements marked data-live are replaced in place by
    the page script when something changes (see /poll); data-keep elements inside them survive."""
    version, pending = state
    tabs = []
    for href, key, label in TABS:
        current = ' aria-current="page"' if key == active else ""
        count = f' <span class=count aria-label="{pending} waiting">{pending}</span>' if key == "requests" and pending else ""
        tabs.append(f'<a href="{href}"{current}>{_icon(key)}<span class=label>{label}</span>{count}</a>')
    crumb = f'<a class=back href="{e(back[0])}">‹ {e(back[1])}</a>' if back else ""
    return (_head(app, title) + f'<body data-page="{e(active)}" data-pending="{pending}" '
            f'data-version="{version}" data-vapid="{e(app.s.vapid_public)}">'
            '<a class=skip href="#main">Skip to content</a>'
            '<header class=top><a class=brand href="/"><img src="/icon-192.png" alt="" width=24 height=24>'
            f'<span>AWS Permissions</span></a>{_stage(app)}</header>'
            '<div id=offline class=banner role=status hidden>You\'re offline. Nothing is saved until you\'re back.</div>'
            f'<main id=main><div class=wrap>{crumb}<div class=titlebar><h1 data-live=title>{e(heading or title)}</h1>{_stage(app)}</div>'
            f'<div id=flash-slot data-live=flash>{_flash(msg)}</div><div data-live=page>{body}</div>'
            '</div></main>'
            f'<nav class=tabs aria-label="Sections" data-live=nav>{"".join(tabs)}</nav>'
            '<dialog id=confirm class=confirm aria-labelledby=confirm-text><form method=dialog>'
            '<p id=confirm-text></p><div class=decide><button value=cancel type=submit>Cancel</button>'
            '<button value=ok type=submit id=confirm-ok class=primary>Confirm</button></div></form></dialog>'
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


def _verb(action):
    return action.split(":", 1)[1] if ":" in action else action


def _is_read(verb):
    return verb.startswith(READ_VERBS) and "*" not in verb and "?" not in verb


def _everything(resources):
    return "*" in resources


def risk(actions, resources):
    """How much a request (or grant) allows, as (level, label). Levels, worst first:
    full: a whole service (svc:*) or everything; broad: wildcard actions, writes on every resource,
    or IAM changes; write: specific write actions on named resources; read: read-only actions."""
    verbs = [_verb(a) for a in actions]
    if "*" in actions or any(v == "*" for v in verbs):
        level = "full"
    elif (any("*" in v or "?" in v for v in verbs) or any(a.startswith("iam:") and not _is_read(_verb(a)) for a in actions)
          or (_everything(resources) and not all(_is_read(v) for v in verbs))):
        level = "broad"
    elif all(_is_read(v) for v in verbs):
        level = "read"
    else:
        level = "write"
    return level, LABELS[level]


LABELS = {"read": "Read-only", "write": "Scoped", "broad": "Broad", "full": "Full access"}
LEVELS = list(LABELS)


def _level_chip(level):
    return f'<span class="chip risk-{level}">{LABELS[level]}</span>'


def _risk_chip(actions, resources):
    return _level_chip(risk(actions, resources)[0])


def _worst_chip(statements):
    """A project's label is its riskiest grant, each graded on its own: a read-everything grant
    next to a scoped write grant must not add up to a broad write."""
    return _level_chip(max((risk(_list(s.get("Action", [])), _list(s.get("Resource", [])))[0] for s in statements),
                           key=LEVELS.index))


def _summary(actions, resources):
    """One line a person can read: '2 S3 actions on 1 resource', '1 DynamoDB action on all resources'."""
    services = sorted({_service(a) for a in actions})
    names = services[0] if len(services) == 1 else ", ".join(services[:-1]) + " and " + services[-1]
    where = "all resources" if _everything(resources) else _plural(len(resources), "resource")
    return f"{len(actions)} {names} action{'' if len(actions) == 1 else 's'} on {where}"


def login_page(app, error="", next_path="/"):
    from urllib.parse import urlencode
    href = "/login" + ("?" + urlencode({"next": next_path}) if next_path != "/" else "")
    msg = f'<p class="flash error" role="alert">{e(error)}</p>' if error else ""
    deep = ("<p class=muted>Sign in to see the request you opened.</p>"
            if next_path.startswith(("/requests/", "/connect/")) else "")
    return (_head(app, "Sign in") + '<body data-page="login" class=center><main id=main><div class=signin>'
            '<img src="/icon-192.png" alt="" width=72 height=72>'
            f'<h1>AWS Permissions {_stage(app)}</h1>'
            '<p class=muted>Approve what your agents ask for.</p>' + msg + deep +
            f'<p><a class="button primary wide" href="{e(href)}">Sign in</a></p>'
            '</div></main></body></html>')


def error_page(app, text, back="/"):
    return (_head(app, "Problem") + '<body data-page="error" class=center><main id=main><div class=signin>'
            f'<h1>Something went wrong</h1><p class="flash error" role="alert">{e(text)}</p>'
            f'<p><a class="button wide" href="{e(back)}">Back to AWS Permissions</a></p></div></main></body></html>')


# ---------- requests ----------

def _scope_notes(r):
    notes = []
    for a in r["actions"]:
        verb = _verb(a)
        if verb == "*":
            notes.append(f"<code>{e(a)}</code> allows <b>every {e(_service(a))} action</b>, including deleting things.")
        elif "*" in verb or "?" in verb:
            notes.append(f"<code>{e(a)}</code> matches several {e(_service(a))} actions.")
    if _everything(r["resources"]) and not all(_is_read(_verb(a)) for a in r["actions"]):
        notes.append("Applies to <b>every resource in the account</b>, not just this project's.")
    return notes


def request_body(app, r, projects, back="/"):
    """What's inside an open request: the grant in plain words, warnings, the exact policy and the
    decision buttons."""
    rid, project = r["id"], r["project"]
    new = project not in projects
    stmt = policy.statement(rid, r["actions"], r["resources"])
    on = ("<span>all resources in the account</span>" if _everything(r["resources"])
          else f'<ul class=codes>{_codes(r["resources"])}</ul>')
    out = [f'<div class=grant><dl><dt>Allow</dt><dd><ul class=codes>{_codes(r["actions"])}</ul></dd>'
           f'<dt>On</dt><dd>{on}</dd><dt>From</dt><dd>{e(r.get("requester") or "unknown")}, {_time(r["created_at"])}</dd></dl>']
    notes = _scope_notes(r)
    if len(notes) == 1:
        out.append(f'<p class=warn>{notes[0]}</p>')
    elif notes:
        out.append('<ul class=warn>' + "".join(f"<li>{n}</li>" for n in notes) + "</ul>")
    if new:
        out.append(f'<p class=note>Creates the project and its role <code>{e(policy.role_name(project))}</code>.</p>')
    out.append(f'<details class=policy><summary>Policy JSON</summary><pre>{e(json.dumps(stmt, indent=2))}</pre></details>')
    if r["status"] == "pending":
        level, label = risk(r["actions"], r["resources"])
        confirm = (f"Approve {label.lower()} ({', '.join(a for a in r['actions'] if '*' in a) or 'every resource'}) "
                   f"for {project}?" if level in ("full", "broad") else "")
        out.append('<div class=decide>'
                   + _form({"op": "approve", "id": rid, "digest": r["digest"]}, "Approve", "primary", confirm, back)
                   + _form({"op": "reject", "id": rid, "digest": r["digest"]}, "Reject", "danger", "", back)
                   + "</div>")
    out.append("</div>")
    return "".join(out)


def request_row(app, r, projects):
    """A pending request in the list: project, reason and risk up front; tap to open in place."""
    rid = r["id"]
    new = '<span class="chip new">new project</span>' if r["project"] not in projects else ""
    return (f'<details class="row request" id="req-{rid}"><summary>'
            f'<span class=head><b>{e(r["project"])}</b>{new}<span class=right><span>#{rid}</span>{_time(r["created_at"])}</span></span>'
            f'<span class=reason>{e(r["reason"])}</span>'
            f'<span class=line>{_risk_chip(r["actions"], r["resources"])}<span class=muted>{e(_summary(r["actions"], r["resources"]))}</span></span>'
            f'</summary>{request_body(app, r, projects)}</details>')


def connect_card(c, back="/"):
    code = c["code"]
    return (f'<article class="card connect" id="connect-{e(code)}" aria-labelledby="connect-{e(code)}-t">'
            f'<p class=head><b id="connect-{e(code)}-t">Connect “{e(c["name"])}”?</b>'
            f'<span class=right>{_time(c["created_at"])}</span></p>'
            f'<p class=code-check>Code <b class=code>{e(code)}</b></p>'
            '<p class=muted>Approve if the agent shows this code.</p><div class=decide>'
            + _form({"op": "approve_connect", "code": code}, "Approve", "primary", "", back)
            + _form({"op": "reject_connect", "code": code}, "Reject", "danger", "", back) + "</div></article>")


def _status_chip(status):
    return f'<span class="chip s-{e(status)}">{e(status.capitalize())}</span>'


def requests_page(app, owner, msg=""):
    st, store = state(app), app.store
    pending, connects, projects = store.list(status="pending"), store.connects(), store.projects()
    out = ['<p class="nudge" id="push-nudge" hidden><a href="/settings">Turn on notifications</a> to hear about '
           'new requests.</p>']
    for c in connects:
        out.append(connect_card(c))
    if pending:
        out.append('<div class=rows>' + "".join(request_row(app, r, projects) for r in pending) + "</div>")
    if not pending and not connects:
        out.append('<div class=empty><p><b>Nothing waiting.</b></p><p class=muted>New requests show up here.</p></div>')
    history = [r for r in store.list() if r["status"] != "pending"][:10]
    if history:
        out.append('<h2 class=section>Decided</h2><ul class=list>')
        for r in history:
            out.append(f'<li class=link-row><a href="/requests/{r["id"]}"><span><b>{e(r["project"])}</b> <span class=muted>#{r["id"]}</span>'
                       f'<br><span class=muted>{e(_summary(r["actions"], r["resources"]))}</span></span>'
                       f'<span class=right>{_status_chip(r["status"])}<br>{_time(r["decided_at"])}</span></a></li>')
        out.append("</ul>")
    return layout(app, owner, "requests", "Requests", "".join(out), st, msg)


def request_page(app, owner, r, msg="", st=None):
    st, rid = st or state(app), r["id"]
    body = []
    if r["status"] != "pending":
        body.append(f'<p class="flash">This request was {_status_chip(r["status"])} {_time(r["decided_at"])}.'
                    + (f' Note: {e(r["note"])}' if r.get("note") else "")
                    + (' See it in <a href="/projects">Projects</a>.' if r["status"] == "approved" else "") + "</p>")
    body.append(f'<article class="card request open" id="req-{rid}">'
                f'<p class=head><b>{e(r["project"])}</b><span class=right><span>#{rid}</span></span></p>'
                f'<p class=reason>{e(r["reason"])}</p>'
                f'<p class=line>{_risk_chip(r["actions"], r["resources"])}<span class=muted>{e(_summary(r["actions"], r["resources"]))}</span></p>'
                + request_body(app, r, app.store.projects(), back=f"/requests/{rid}") + "</article>")
    body.append(history(rid, app.store.events(rid)))
    return layout(app, owner, "requests", f"Request #{rid}", "".join(body), st, msg, back=("/", "Requests"))


# What each IAM change is called in a request's History: (done, attempted).
EVENT_LABELS = {"approve": ("Approved", "Approval"), "revoke": ("Revoked", "Revoke"),
                "sync_project": ("Re-applied", "Re-apply"), "remove_project": ("Project deleted", "Project deletion")}


def history(rid, events):
    """The IAM changes made for this request, plus any change for another request that added or
    removed this one's grant (for example a re-apply after a failed revoke). See App.iam_change."""
    rows, sid = [], policy.sid(rid)
    for ev in events:
        done, tried = EVENT_LABELS.get(ev["op"], (ev["op"], ev["op"]))
        if rid in ev.get("targets", []):
            what = done if ev["outcome"] == "applied" else f'{tried} {ev["outcome"]}'
            if ev.get("detail"):
                what += f': {ev["detail"]}'
        elif ev["outcome"] != "applied" or (sid in ev.get("previous_grants", [])) == (sid in ev.get("grants", [])):
            continue  # another request's change that left this grant as it was
        else:
            what = f'Grant {"added" if sid in ev["grants"] else "removed"} ({tried.lower()})'
        error = f'<br><span class=muted>{e(ev["error"])}</span>' if ev.get("error") else ""
        rows.append(f'<li><span><b>{e(what)}</b> <span class=muted>by {e(ev.get("actor") or "unknown")}</span>{error}</span>'
                    f'<span class=right>{_time(ev["at"])}</span></li>')
    if not rows:
        return ""
    out = ['<h2 class=section>History</h2><ul class="list history">', *rows]
    return "".join(out) + "</ul>"


def connect_page(app, owner, code, msg=""):
    st = state(app)
    match = [c for c in app.store.connects() if c["code"] == code]
    if match:
        body = connect_card(match[0], back=f"/connect/{code}")
    else:
        body = ('<div class=empty><p><b>This connect request is no longer waiting.</b></p><p class=muted>It was '
                'approved, rejected or expired. Connect again from the agent.</p></div>')
    return layout(app, owner, "requests", "Connect an agent", body, st, msg, back=("/", "Requests"))


# ---------- projects ----------

def _grant(project, s, store):
    sid = s.get("Sid", "")
    req = store.get(int(sid[3:])) if sid.startswith("Req") and sid[3:].isdigit() else None
    actions, resources = _list(s.get("Action", [])), _list(s.get("Resource", []))
    on = ("<span>all resources</span>" if _everything(resources) else f'<ul class=codes>{_codes(resources)}</ul>')
    why = (f'<p class=muted>{e(req["reason"])} <a href="/requests/{req["id"]}">#{req["id"]}</a></p>' if req
           else f'<p class=muted>Grant <code>{e(sid)}</code></p>')
    return (f'<li><div><p class=line>{_risk_chip(actions, resources)}</p><ul class=codes>{_codes(actions)}</ul>'
            f'<p class=on>on {on}</p>{why}</div>'
            + _form({"op": "revoke", "project": project, "sid": sid}, "Revoke", "danger small",
                    f"Revoke this grant from {project}? Agents lose it within minutes.", "/projects") + "</li>")


def projects_page(app, owner, msg=""):
    st, store, broker = state(app), app.store, app.broker
    projects = store.projects()
    out = []
    if not projects:
        out.append('<div class=empty><p><b>No projects yet.</b></p><p class=muted>A project is created the first '
                   'time you approve a request for it.</p></div>')
    else:
        out.append("<div class=rows>")
    for project in projects:
        grants = broker.grants(project)
        statements = grants["Statement"] if grants else []
        synced = broker.in_sync(project, store.approved(project))
        worst = _worst_chip(statements) if statements else ""
        warn = '<span class="chip risk-full">IAM mismatch</span>' if not synced else ""
        out.append(f'<details class="row project" id="project-{e(project)}"><summary>'
                   f'<span class=head><b>{e(project)}</b><span class=right>{_plural(len(statements), "grant")}</span></span>'
                   f'<span class=line>{warn}{worst}<span class=muted>profile <code>apm-{e(project)}</code></span></span></summary>')
        if not synced:
            out.append('<div class=warn role=alert><p><b>IAM doesn\'t match your decisions.</b> An update failed; '
                       'the grants below may be wrong until you re-apply.</p>'
                       + _form({"op": "sync_project", "project": project}, "Re-apply decisions", "primary", "", "/projects")
                       + "</div>")
        if not statements:
            out.append("<p class=muted>No grants yet.</p>")
        else:
            out.append("<ul class=grants>" + "".join(_grant(project, s, store) for s in statements) + "</ul>")
        out.append(f'<p class=muted>Role <code>{e(policy.role_name(project))}</code></p>'
                   '<details class=danger-zone><summary>Delete project…</summary>'
                   '<p class=muted>Removes the role and every grant. Agents lose access within an hour.</p>'
                   + _form({"op": "remove_project", "project": project}, f"Delete {project}", "danger",
                           f"Delete project {project} and all its grants?", "/projects")
                   + "</details></details>")
    if projects:
        out.append("</div>")
    return layout(app, owner, "projects", "Projects", "".join(out), st, msg)


# ---------- settings: notifications, keys, account ----------

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


def settings_page(app, owner, msg="", new_key=None):
    st, subs, keys = state(app), app.store.subscriptions(), app.store.keys()
    out = []
    if new_key:
        out.append('<section class="card new-key" aria-labelledby=new-key-t><h2 id=new-key-t>Copy your new key now</h2>'
                   "<p class=muted>It won't be shown again.</p>"
                   f'<p class=secret id=secret>{e(new_key)}</p><p><button id=copy-key data-target=secret class=primary>Copy key</button></p>'
                   "<p class=muted>Run <code>apm login --paste</code> on the agent's machine, or set "
                   "<code>APM_API_KEY</code>.</p></section>")
    # data-keep: this card is driven by the page script, so live refreshes leave it alone.
    out.append('<h2 class=section>Notifications</h2>'
               '<section class=card id=this-device data-keep aria-labelledby=push-status>'
               '<p id=push-status aria-live=polite>Checking notifications…</p>'
               '<div class=decide>'
               '<button id=push-enable class=primary hidden>Turn on notifications</button>'
               '<button id=push-test hidden>Send a test</button>'
               '<button id=push-disable class=danger hidden>Turn off</button>'
               '<button id=install-app hidden>Install app</button></div>'
               '<div id=install-ios class=steps hidden><p>Notifications need the Home Screen app: in Safari tap '
               '<b>Share</b>, then <b>Add to Home Screen</b>, and open it from there.</p></div>'
               '<div id=push-denied class=steps hidden><p id=push-denied-help></p></div>'
               '</section>')
    if not subs:
        out.append('<p class=muted>No devices yet.</p>')
    else:
        out.append('<ul class="list devices">')
        for s in subs:
            out.append(f'<li data-device="{e(s["pk"])}"><span><b>{e(_device(s["label"]))}</b>'
                       '<span class="chip this" hidden>This device</span>'
                       f'<br><span class=muted>{_health(s)}, added {_time(s["created_at"])}</span></span>'
                       + _form({"op": "delete_device", "pk": s["pk"]}, "Remove", "danger small",
                               "Stop notifications to this device?", "/settings") + "</li>")
        out.append("</ul>")
    out.append('<p class=muted>Request notifications show the project, request number and action count.</p>')

    out.append('<h2 class=section>Agent keys</h2>')
    if keys:
        out.append('<ul class=list>')
        for k in keys:
            out.append(f'<li><span><b>{e(k["name"])}</b> <code>{e(k["prefix"])}…</code><br>'
                       f'<span class=muted>{"Last used " + _time(k["last_used"]) if k["last_used"] else "Never used"}, '
                       f'created {_time(k["created_at"])}</span></span>'
                       + _form({"op": "delete_key", "pk": k["pk"]}, "Delete", "danger small",
                               f"Delete key {k['name']}? Agents using it stop working.", "/settings") + "</li>")
        out.append("</ul>")
    else:
        out.append('<p class=muted>No keys yet. Agents with the plugin connect themselves.</p>')
    out.append('<form method="post" action="/action" class=create><input type="hidden" name="op" value="create_key">'
               '<input type="hidden" name="back" value="/settings">'
               '<label for=key-name class=sr-only>New key name</label><div class=field>'
               '<input type="text" id=key-name name="name" placeholder="New key name, e.g. macbook" maxlength="40" required '
               'autocomplete=off autocapitalize=off>'
               '<button>Create key</button></div></form>'
               '<p class=muted>Keys let agents ask for access. They can never approve it.</p>')

    out.append('<h2 class=section>Account</h2><section class=card>'
               f'<p><b>{e(owner)}</b><br><span class=muted>AWS account {e(app.broker.account)}, {e(app.broker.region)}</span></p>'
               '<form method=post action="/logout" data-native><button class=danger>Sign out</button></form></section>')
    return layout(app, owner, "settings", "Settings", "".join(out), st, msg)


def _list(v):
    return v if isinstance(v, list) else [v]
