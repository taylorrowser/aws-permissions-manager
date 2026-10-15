"""HTML for the owner web app. Server-rendered; static/app.js adds live refresh, in-page submits,
confirm dialogs, local times, offline handling, install help and push notification sign-up.

Screens: Requests (/, /requests/<id>, /connect/<code>: a list and a reading pane), Projects
(/projects) and Settings (/settings: notifications, agent keys, account). Every list leads with
what matters on a phone: project, reason and how risky the request is."""
import html
import json
import re
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
            '<meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">'
            '<meta name="theme-color" content="#09090b" media="(prefers-color-scheme: dark)">'
            '<meta name="color-scheme" content="light dark">'
            '<link rel="manifest" href="/manifest.webmanifest"><link rel="apple-touch-icon" href="/apple-touch-icon.png">'
            f'<link rel="icon" href="/icon-192.png"><title>{e(stage + title)} · AWS Permissions</title>'
            f'<link rel="stylesheet" href="/app.css?v={v}"><script src="/app.js?v={v}" defer></script></head>')


def _stage(app):
    return "" if app.s.stage == "prod" else f'<span class=stage title="Not production">{e(app.s.stage)}</span>'


def _flash(msg):
    if not msg:
        return ""
    return f'<p class="flash error" role="alert" tabindex="-1" id="flash">{e(msg)}</p>'


def _split(msg):
    """(error, toast): errors stay inline where they happened; anything else is a toast."""
    return (msg, "") if msg.startswith("Error") else ("", msg)


def state(app):
    """Call first in every page: (fingerprint, pending count) read before the body, so anything
    that changes while rendering shows up on the next poll (see web.state_version)."""
    from .web import state_version
    return state_version(app.store)


def layout(app, owner, active, title, body, state, msg="", heading=None, back=None, toast="", view=None):
    """The app shell. The body never scrolls: only <main> does (or, on Requests, its two panes), so
    the tab bar stays put on iOS (no position:fixed, no viewport units). From 900px the tabs are a
    sidebar. Elements marked data-live are replaced in place by the page script when something
    changes (see /poll); data-keep elements inside them survive. view: Requests passes its panes as
    the body, with their own title and messages; "list" or "item" says which one a phone shows."""
    version, pending = state
    if not view:
        error, toast = _split(msg) if msg else ("", toast)
    tabs = []
    for href, key, label in TABS:
        current = ' aria-current="page"' if key == active else ""
        count = f' <span class=count aria-label="{pending} waiting">{pending}</span>' if key == "requests" and pending else ""
        tabs.append(f'<a href="{href}"{current}>{_icon(key)}<span class=label>{label}</span>{count}</a>')
    if view:
        main = f'<main id=main class=inbox data-view="{view}">{body}</main>'
    else:
        crumb = f'<a class=back href="{e(back[0])}">{e(back[1])}</a>' if back else ""
        main = (f'<main id=main><div class=wrap>{crumb}<div class=titlebar><h1 data-live=title>{e(heading or title)}</h1>'
                f'{_stage(app)}</div><div id=flash-slot data-live=flash>{_flash(error)}</div>'
                f'<div data-live=page>{body}</div></div></main>')
    return (_head(app, title) + f'<body data-page="{e(active)}" data-pending="{pending}" '
            f'data-version="{version}" data-vapid="{e(app.s.vapid_public)}">'
            '<a class=skip href="#main">Skip to content</a>'
            '<header class=top><a class=brand href="/"><img src="/icon-192.png" alt="" width=24 height=24>'
            f'<span>AWS Permissions</span></a>{_stage(app)}</header>'
            '<div id=offline class=banner role=status hidden>You\'re offline. Nothing is saved until you\'re back.</div>'
            + main +
            f'<nav class=tabs aria-label="Sections" data-live=nav>{"".join(tabs)}</nav>'
            f'<div id=toast class=toast role=status>{e(toast)}</div>'
            '<dialog id=confirm class=confirm aria-labelledby=confirm-text><form method=dialog>'
            '<p id=confirm-text></p><div class=decide><button value=cancel type=submit>Cancel</button>'
            '<button value=ok type=submit id=confirm-ok class=primary>Confirm</button></div></form></dialog>'
            '</body></html>')


def _form(fields, label, cls="", confirm="", back="/", form_id=""):
    """A one-button form. form_id lets inputs elsewhere on the page join it (form="<id>")."""
    fields = {**fields, "back": back}
    hidden = "".join(f'<input type="hidden" name="{e(k)}" value="{e(str(v))}">' for k, v in fields.items())
    data = f' data-confirm="{e(confirm)}"' if confirm else ""
    ident = f' id="{e(form_id)}"' if form_id else ""
    return f'<form method="post" action="/action"{ident}{data}>{hidden}<button class="{cls}">{e(label)}</button></form>'


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


LABELS = {"read": "Read-only", "write": "Scoped write", "broad": "Broad", "full": "Full access"}
LEVELS = list(LABELS)


def _level_label(level):
    """Risk is a coloured dot and a word: the only colour on the page besides Approve and Reject."""
    return f'<span class="risk risk-{level}"><span class=dot aria-hidden="true"></span>{LABELS[level]}</span>'


def _risk_chip(actions, resources):
    return _level_label(risk(actions, resources)[0])


def _worst_chip(statements):
    """A project's label is its riskiest grant, each graded on its own: a read-everything grant
    next to a scoped write grant must not add up to a broad write."""
    return _level_label(worst_risk([{"actions": _list(s.get("Action", [])), "resources": _list(s.get("Resource", []))}
                                    for s in statements]))


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


# ---------- requests: an inbox ----------
# A list of what needs a decision, and a reading pane. On wide screens both show side by side and
# the page script swaps the pane in place; on phones the list (/) and a request (/requests/<id>)
# are separate pages. Both URLs render the same two panes; data-view says which one a phone shows.

def grants_of(r):
    """The grants a request asks for, each {"actions", "resources"}. Everything on the card is per
    grant: requests carry one today, and a request with several returns one entry per grant here."""
    return [{"actions": r["actions"], "resources": r["resources"]}]


def worst_risk(grants):
    """A request is as risky as its riskiest grant, each graded on its own."""
    return max((risk(g["actions"], g["resources"])[0] for g in grants), key=LEVELS.index)


def _kinds(r, projects):
    """Small badges for what kind of request this is."""
    return ["New project"] if r["project"] not in projects else []


def _badges(labels):
    return "".join(f'<span class=badge>{e(x)}</span>' for x in labels)


def inbox(app, owner, st, msg="", item=None):
    """The Requests screen. item: None (the list), ("request", r) or ("connect", code)."""
    store = app.store
    requests, connects = store.list(), store.connects()
    projects = {r["project"] for r in requests if r["status"] in ("approved", "revoked")}  # as store.projects()
    pending = [r for r in requests if r["status"] == "pending"]
    error, toast = _split(msg)
    kind, it = item or (None, None)
    selected = f"req-{it['id']}" if kind == "request" else f"connect-{it}" if kind == "connect" else ""

    rows = [_connect_row(c, selected) for c in connects] + [_request_row(r, projects, selected) for r in pending]
    out = ['<p class="nudge" id="push-nudge" hidden><a href="/settings">Turn on notifications</a> to hear about '
           'new requests.</p>']
    if not item:
        out.append(f'<div id=flash-slot>{_flash(error)}</div>')
    if rows:
        out.append('<ul class=items aria-label="Waiting">' + "".join(rows) + "</ul>")
    else:
        out.append('<div class=empty><p><b>Nothing waiting.</b></p><p class=muted>New requests show up here.</p></div>')
    decided, before = decided_rows(requests, selected=selected)
    if decided:
        out.append(f'<details class=decided id=decided><summary>Decided</summary><ul class=items id=decided-list>'
                   f'{decided}{_more(before)}</ul></details>')

    if kind == "request":
        pane, title = request_pane(app, it, projects, error if item else ""), it["project"]
    elif kind == "connect":
        match = [c for c in connects if c["code"] == it]
        pane, title = connect_pane(match[0] if match else None, it, error), "Connect an agent"
    else:
        pane, title = ('<section class=pane data-live=pane data-id="" aria-label="Request">'
                       '<div class="pane-body pane-empty"><p class=muted>Select a request</p></div></section>'), "Requests"
    body = ('<div class=list-pane><div class=titlebar><h1 data-live=title>Requests</h1>' + _stage(app) + '</div>'
            f'<div data-live=list>{"".join(out)}</div></div>{pane}')
    return layout(app, owner, "requests", title, body, st, toast=toast, view="item" if item else "list")


def _request_row(r, projects, selected):
    rid = r["id"]
    current = ' aria-current="true"' if selected == f"req-{rid}" else ""
    return (f'<li><a class=item href="/requests/{rid}" id="req-{rid}"{current}><span class=item-top>'
            f'<b>{e(r["project"])}</b>{_badges(_kinds(r, projects))}{_level_label(worst_risk(grants_of(r)))}</span>'
            f'<span class=reason>{e(r["reason"])}</span></a></li>')


def _connect_row(c, selected):
    code = e(c["code"])
    current = ' aria-current="true"' if selected == f"connect-{c['code']}" else ""
    return (f'<li><a class=item href="/connect/{code}" id="connect-{code}"{current}><span class=item-top>'
            f'<b>{e(c["name"])}</b><span class=badge>Connect</span></span></a></li>')


DECIDED_PAGE = 10
STATUS_WORDS = {"approved": "Approved", "rejected": "Rejected", "revoked": "Revoked"}


def decided_rows(requests, before=None, selected=""):
    """One page of decided requests, newest first, below request id `before`: (rows, next before)."""
    done = [r for r in requests if r["status"] != "pending" and (before is None or r["id"] < before)]
    page = done[:DECIDED_PAGE]
    rows = []
    for r in page:
        current = ' aria-current="true"' if selected == f"req-{r['id']}" else ""
        rows.append(f'<li><a class=item href="/requests/{r["id"]}" id="req-{r["id"]}"{current}><span class=item-top>'
                    f'<b>{e(r["project"])}</b><span class=state>{e(STATUS_WORDS.get(r["status"], r["status"]))}</span></span>'
                    f'<span class=reason>{e(r["reason"])}</span></a></li>')
    return "".join(rows), (page[-1]["id"] if len(done) > DECIDED_PAGE else None)


def _more(before):
    return (f'<li class=more data-before="{before}"><button type=button class=quiet>Older</button></li>'
            if before else "")


def decided_page(app, before):
    """GET /decided?before=<id>: the next page of the Decided list, for the page script."""
    rows, nxt = decided_rows(app.store.list(), before)
    return {"html": rows + _more(nxt), "before": nxt}


# ----- the plain-English line for a grant -----

# CamelCase verbs that read as themselves when the action's object is the resource it names
# ("UpdateService" on a service). Anything else is "Write".
VERB_WORDS = {"Create": "Create", "Delete": "Delete", "Update": "Update", "Put": "Write", "Invoke": "Invoke",
              "Start": "Start", "Stop": "Stop", "Reboot": "Reboot", "Terminate": "Terminate", "Run": "Run",
              "Send": "Send", "Publish": "Publish", "Pass": "Pass", "Tag": "Tag", "Untag": "Untag",
              "Modify": "Change", "Restore": "Restore", "Attach": "Attach", "Detach": "Detach"}
# ARNs whose resource part is just a name, with no type in front.
BARE_NAMES = {"sqs": "queue", "sns": "topic"}


def _wild(text):
    return "*" in text or "?" in text


def _reads(verb):
    """Read-only, including wildcards that only cover reads (Get*, List*)."""
    return verb.rstrip("*?").startswith(READ_VERBS) if _wild(verb) else _is_read(verb)


def _where(arn):
    """(kind, phrase) for one resource: ("bucket", "bucket order-exports"), ("table", "every table
    matching orders-*"). Wildcards are always said."""
    parts = arn.split(":", 5)
    if len(parts) < 6 or not parts[5]:
        return "", f"resource {arn}"
    service, region, account, rest = parts[2], parts[3], parts[4], parts[5]
    if service == "s3":
        bucket, _, path = rest.partition("/")
        kind, name, extra = "bucket", bucket, f" ({path})" if path and path != "*" else ""
    else:
        m = re.match(r"([A-Za-z][A-Za-z0-9-]*)[/:](.*)$", rest)
        kind, name, extra = (m.group(1), m.group(2), "") if m else (BARE_NAMES.get(service, "resource"), rest, "")
    if name in ("", "*"):
        phrase = f"every {kind}"
    elif _wild(name):
        phrase = f"every {kind} matching {name}"
    else:
        phrase = f"{kind} {name}"
    spread = [w for w, v in (("region", region), ("account", account)) if _wild(v)]
    return kind.lower(), phrase + extra + (f" in every {' and '.join(spread)}" if spread else "")


def _and(items):
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def plain(actions, resources):
    """One line a person can read, from a grant's actions and resources: "Read S3 bucket
    order-exports", "Update ECS service api", "Do anything in DynamoDB, on every resource". It never
    understates scope: wildcard actions, wildcard names and every resource are always said."""
    every = "*" in resources
    places = [] if every else [_where(r) for r in resources]
    kinds = {k for k, _ in places}
    services = {}
    for a in actions:
        service, _, verb = a.partition(":")
        services.setdefault(service, []).append(verb or "*")
    clauses = []
    for service, verbs in services.items():
        name = "AWS" if service == "*" else SERVICES.get(service, service)
        if "*" in verbs:
            clauses.append(("Do anything in", name, ""))
            continue
        reads = [v for v in verbs if _reads(v)]
        if len(reads) == len(verbs):
            word = "Read"
        elif reads:
            word = "Read and write"
        else:
            word = "Write"
            first = re.match(r"([A-Z][a-z]+)(\w*)$", verbs[0]) if len(verbs) == 1 else None
            if first and first.group(1) in VERB_WORDS and len(kinds) == 1 and first.group(2).lower().startswith(kinds.pop()):
                word = VERB_WORDS[first.group(1)]
        wild = [v for v in verbs if _wild(v)]
        clauses.append((word, name, f" (any {' or '.join(wild)} action)" if wild else ""))
    if every:
        where = ", on every resource"
    else:
        phrases = list(dict.fromkeys(p for _, p in places))  # bucket b and b/* read as one bucket
        if len(phrases) > 3:
            wide = [p for p in phrases if re.search(r"\bevery\b", p)]  # every bucket, in every region, ...
            phrases = [f"{len(phrases)} resources" + (", including " + _and(wide) if wide else "")]
        listing = _and(phrases)
    if len(clauses) == 1 and clauses[0][0] != "Do anything in":
        word, name, wild = clauses[0]
        if every:
            return f"{word} {name}{wild}{where}"
        return f"{word} {name}{' ' if listing[0].isalpha() and not listing.startswith('every') else ' on '}{listing}{wild}"
    joined = " and ".join((w if i == 0 else w[0].lower() + w[1:]) + f" {n}{x}" for i, (w, n, x) in enumerate(clauses))
    return joined + (where if every else f" on {listing}")


def _scope_notes(actions, resources):
    notes = []
    for a in actions:
        verb = _verb(a)
        if verb == "*":
            notes.append(f"<code>{e(a)}</code> is every {e(_service(a))} action, including deletes.")
        elif _wild(verb):
            notes.append(f"<code>{e(a)}</code> matches several {e(_service(a))} actions.")
    if _everything(resources) and not all(_is_read(_verb(a)) for a in actions):
        notes.append("Applies to every resource in the account, not just this project's.")
    if policy.resource_policy_actions(actions):
        on = "every resource it covers" if _everything(resources) else "this resource" if len(resources) == 1 else "these resources"
        notes.append(f"Can grant anyone anything on {on}.")
    return notes


def _grant_card(g):
    """One grant: the plain line and its risk, what it means, then the exact actions and ARNs."""
    actions, resources = g["actions"], g["resources"]
    notes = _scope_notes(actions, resources)
    return (f'<section class=grant><p class=grant-head><span class=plain>{e(plain(actions, resources))}</span>'
            f'{_level_label(risk(actions, resources)[0])}</p>'
            + ('<ul class=notes>' + "".join(f"<li>{n}</li>" for n in notes) + "</ul>" if notes else "")
            + f'<ul class=codes>{_codes(actions)}</ul><ul class=codes>{_codes(resources)}</ul></section>')


def request_pane(app, r, projects, error=""):
    """An open request: what it asks for in plain words, per grant, then Details, then the decision."""
    rid, project = r["id"], r["project"]
    grants, pending = grants_of(r), r["status"] == "pending"
    events = app.store.events(rid)
    failed = any(ev["outcome"] != "applied" and rid in ev.get("targets", []) for ev in events)
    out = [f'<section class=pane data-live=pane data-id="req-{rid}" aria-labelledby=pane-title><div class=pane-body>'
           '<a class=back href="/">Requests</a>'
           f'<header class=pane-head><h2 id=pane-title>{e(project)}</h2>{_badges(_kinds(r, projects))}</header>'
           f'<p class=reason>{e(r["reason"])}</p>']
    if not pending:
        out.append(f'<p class=status>{e(STATUS_WORDS.get(r["status"], r["status"]))} {_time(r["decided_at"])}'
                   + (f'. {e(r["note"])}' if r.get("note") else "")
                   + ('. See it in <a href="/projects">Projects</a>.' if r["status"] == "approved" else "") + "</p>")
        out.append(f'<div id=flash-slot>{_flash(error)}</div>')
    out += [_grant_card(g) for g in grants]
    if project not in projects and pending:
        out.append(f'<p class=note>Creates the project and its role <code>{e(policy.role_name(project))}</code>.</p>')
    stmt = policy.statement(rid, r["actions"], r["resources"])
    out.append(f'<details class=more id="details-{rid}"><summary>Details</summary><dl class=meta>'
               f'<dt>From</dt><dd>{e(r.get("requester") or "unknown")}</dd><dt>Asked</dt><dd>{_time(r["created_at"])}</dd>'
               f'<dt>Role</dt><dd><code>{e(policy.role_name(project))}</code></dd></dl>'
               f'<pre>{e(json.dumps(stmt, indent=2))}</pre>{"" if failed else history(rid, events)}</details>')
    if failed:  # an IAM change for this request failed: say so up front
        out.append(history(rid, events))
    out.append("</div>")
    if pending:
        level = worst_risk(grants)
        wild = ", ".join(a for g in grants for a in g["actions"] if "*" in a) or "every resource"
        confirm = f"Approve {LABELS[level].lower()} ({wild}) for {project}?" if level in ("full", "broad") else ""
        back = f"/requests/{rid}"
        out.append(f'<div class=pane-actions><div id=flash-slot>{_flash(error)}</div><div class=decide>'
                   + _form({"op": "approve", "id": rid, "digest": r["digest"]}, "Approve", "approve", confirm, back,
                           form_id=f"approve-{rid}")
                   + _form({"op": "reject", "id": rid, "digest": r["digest"]}, "Reject", "reject", "", back)
                   + "</div></div>")
    return "".join(out) + "</section>"


def connect_pane(c, code, error=""):
    out = [f'<section class=pane data-live=pane data-id="connect-{e(code)}" aria-labelledby=pane-title>'
           '<div class=pane-body><a class=back href="/">Requests</a>']
    if not c:
        out.append('<div class=empty><p><b>This connect request is no longer waiting.</b></p><p class=muted>It was '
                   'approved, rejected or expired. Connect again from the agent.</p></div>'
                   f'<div id=flash-slot>{_flash(error)}</div></div></section>')
        return "".join(out)
    back = f"/connect/{c['code']}"
    out.append(f'<header class=pane-head><h2 id=pane-title>{e(c["name"])}</h2><span class=badge>Connect</span></header>'
               '<p class=reason>Approve if the agent shows this code.</p>'
               f'<p class=code>{e(c["code"])}</p><p class=muted>{_time(c["created_at"])}</p></div>'
               f'<div class=pane-actions><div id=flash-slot>{_flash(error)}</div><div class=decide>'
               + _form({"op": "approve_connect", "code": c["code"]}, "Approve", "approve", "", back)
               + _form({"op": "reject_connect", "code": c["code"]}, "Reject", "reject", "", back)
               + "</div></div></section>")
    return "".join(out)


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
                    f'<span class=muted>{_time(ev["at"])}</span></li>')
    if not rows:
        return ""
    return '<section class=history><h3>History</h3><ul>' + "".join(rows) + "</ul></section>"


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
        warn = '<span class=badge>IAM mismatch</span>' if not synced else ""
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
                       '<span class="badge this" hidden>This device</span>'
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
