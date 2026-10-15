"""The usage audit: when each grant of a project was last used, from IAM Access Advisor. Read-only."""
import fnmatch

UNUSED_DAYS = 30
DELAY_NOTE = "AWS reports usage up to about 4 hours late, so very recent use may not show yet."


def _ts(value):
    if not value:
        return None
    return int(value.timestamp()) if hasattr(value, "timestamp") else int(value)


def _index(services):
    """{service namespace: (service last authenticated, {action name: last accessed or None})}, lowercased."""
    out = {}
    for svc in services or []:
        tracked = {}
        for a in svc.get("TrackedActionsLastAccessed") or []:
            name = a["ActionName"].split(":")[-1].lower()
            tracked[name] = _ts(a.get("LastAccessedTime"))
        out[svc["ServiceNamespace"].lower()] = (_ts(svc.get("LastAuthenticated")), tracked)
    return out


def action_usage(action, index):
    """One granted action's last use. per_action is True only when AWS tracks that exact action;
    wildcards and untracked actions (e.g. S3 data events) fall back to the service's last use."""
    service, _, name = action.lower().partition(":")
    service_last, tracked = index.get(service, (None, {}))
    if "*" not in name and "?" not in name and name in tracked:
        last, per_action, matched = tracked[name], True, None
    else:
        last, per_action = service_last, False
        matched = sorted(f"{service}:{t}" for t, at in tracked.items() if at and fnmatch.fnmatchcase(t, name)) \
            if "*" in name or "?" in name else None
    out = {"action": action, "last_used": last, "per_action": per_action, "used": last is not None}
    if matched is not None:
        out["matched"] = matched
    return out


def grant_usage(stmt, request, index, now):
    """A grant's last use is the newest use of any of its actions. It's unused when nothing has
    used it for UNUSED_DAYS and it was granted at least that long ago."""
    actions = [action_usage(a, index) for a in _list(stmt.get("Action", []))]
    last = max((a["last_used"] for a in actions if a["last_used"]), default=None)
    granted = (request or {}).get("decided_at") or None
    cutoff = now - UNUSED_DAYS * 86400
    return {"grant": stmt.get("Sid", ""), "resources": _list(stmt.get("Resource", [])), "actions": actions,
            "last_used": last, "unused": (last is None or last < cutoff) and granted is not None and granted <= cutoff,
            "granted_at": granted, "expires_at": (request or {}).get("expires_at"),
            "request": request["id"] if request else None, "reason": request["reason"] if request else "",
            "requester": request.get("requester", "") if request else ""}


def report(statements, requests_by_sid, services, now):
    index = _index(services)
    return [grant_usage(s, requests_by_sid.get(s.get("Sid", "")), index, now) for s in statements]


def _list(v):
    return v if isinstance(v, list) else [v]
