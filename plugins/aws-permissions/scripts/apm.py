#!/usr/bin/env python3
"""apm: the agent-side client for AWS Permissions Manager. Standard library only (Python 3.9+).

    apm login [--paste]            connect this machine (owner approves in the browser), or paste a key
    apm projects [--search TEXT]   projects and what each is allowed to do
    apm request --project P -a ACTION [-r ARN] --reason WHY [--wait]
    apm status [ID] | apm wait ID
    apm use PROJECT                set up AWS profile apm-PROJECT (credentials stay out of view)
    apm credentials PROJECT        AWS credential_process helper (used by the profile)
    apm mcp                        MCP server over stdio (Claude Code, Codex)

Settings: APM_URL and APM_API_KEY override ~/.apm/client.json and ~/.apm/api-key.
"""
import argparse
import configparser
import getpass
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.3.0"
DEFAULT_URL = "https://apm.taylorrowser.com"
HOME = Path(os.environ.get("APM_HOME", Path.home() / ".apm"))
CLIENT_FILE = HOME / "client.json"
KEY_FILE = HOME / "api-key"
PENDING_KEY_FILE = HOME / "pending-key"
CACHE = HOME / "cache"
STABLE_COPY = HOME / "bin" / "apm.py"
AWS_CONFIG = Path(os.environ.get("AWS_CONFIG_FILE", Path.home() / ".aws" / "config"))


class ApmError(Exception):
    pass


# ---------- settings and HTTP ----------

def _settings():
    saved = json.loads(CLIENT_FILE.read_text()) if CLIENT_FILE.exists() else {}
    url = (os.environ.get("APM_URL") or saved.get("url") or DEFAULT_URL).rstrip("/")
    key = os.environ.get("APM_API_KEY") or (KEY_FILE.read_text().strip() if KEY_FILE.exists() else "")
    return url, key


def call(method, path, body=None, key=None):
    url, saved_key = _settings()
    key = key or saved_key
    if not key and not path.startswith("/api/connect"):
        raise ApmError("not connected to AWS Permissions yet: call the `connect` tool (or run `apm login`) "
                       "and have the owner approve it")
    headers = {"Content-Type": "application/json", "User-Agent": f"apm-client/{VERSION}"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            message = json.loads(e.read()).get("error", "")
        except Exception:
            message = ""
        raise ApmError(message or f"HTTP {e.code} from {url}")
    except urllib.error.URLError as e:
        raise ApmError(f"can't reach {url}: {e.reason}")


def _private_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


# ---------- operations shared by the CLI and MCP ----------

def connect(wait_seconds=0, open_browser=True):
    """Connect this machine without copying keys around: generate an API key locally, register only its
    hash, and wait for the owner to approve it on the dashboard. Returns (status, code_or_None, url)."""
    url, key = _settings()
    if key:
        try:
            call("GET", "/api/whoami", key=key)
            return "connected", None, url
        except ApmError as e:
            if "invalid API key" not in str(e):
                raise
    pending = json.loads(PENDING_KEY_FILE.read_text()) if PENDING_KEY_FILE.exists() else None
    if pending and pending.get("url") != url:
        pending = None
    if pending:
        status = _poll_connect(pending["key"], wait_seconds)
        if status in ("approved", "pending"):
            return ("connected" if status == "approved" else "pending"), pending["code"], pending["dashboard"]
        PENDING_KEY_FILE.unlink()
        if status == "rejected":
            return "rejected", pending["code"], pending["dashboard"]  # don't re-ask the owner unprompted
    new_key = "apm_" + secrets.token_urlsafe(32)
    name = f"{getpass.getuser()}@{socket.gethostname().split('.')[0]}"
    r = call("POST", "/api/connect", {"name": name, "key_hash": hashlib.sha256(new_key.encode()).hexdigest(),
                                      "prefix": new_key[:10]})
    _private_write(PENDING_KEY_FILE, json.dumps({"key": new_key, "code": r["code"], "dashboard": r["url"], "url": url}))
    if open_browser:
        _open(r["url"])
    status = _poll_connect(new_key, wait_seconds)
    return ("connected" if status == "approved" else status), r["code"], r["url"]


def _poll_connect(key, wait_seconds, poll=3):
    deadline = time.time() + wait_seconds
    while True:
        status = call("POST", "/api/connect/status", {"key": key})["status"]
        if status == "approved":
            _private_write(KEY_FILE, key + "\n")
            PENDING_KEY_FILE.unlink(missing_ok=True)
        if status != "pending" or time.time() >= deadline:
            return status
        time.sleep(min(poll, max(0.0, deadline - time.time())))


def _open(url):
    opener = "open" if sys.platform == "darwin" else "xdg-open" if shutil.which("xdg-open") else None
    if opener and not os.environ.get("APM_NO_BROWSER"):
        subprocess.Popen([opener, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def projects(search=""):
    from urllib.parse import quote
    return call("GET", "/api/projects" + (f"?search={quote(search)}" if search else ""))["projects"]


def request(project, actions, resources, reason):
    return call("POST", "/api/requests", {"project": project, "actions": actions,
                                          "resources": resources or ["*"], "reason": reason})


def get_request(rid):
    return call("GET", f"/api/requests/{int(rid)}")


def wait(rid, timeout, poll=3):
    deadline = time.time() + timeout
    while True:
        r = get_request(rid)
        if r["status"] != "pending" or time.time() >= deadline:
            return r
        time.sleep(min(poll, max(0.0, deadline - time.time())))


def profile_name(project):
    return f"apm-{project}"


def use(project):
    """Point AWS profile apm-<project> at `apm credentials`, then check it works. Returns the profile."""
    fetch_credentials(project, refresh=True)  # fails clearly if nothing is granted yet
    script = _stable_copy()
    region = call("GET", "/api/whoami").get("region", "us-east-1")
    ini = configparser.RawConfigParser()
    ini.read(AWS_CONFIG)
    section = f"profile {profile_name(project)}"
    if not ini.has_section(section):
        ini.add_section(section)
    ini.set(section, "credential_process", f'"{sys.executable}" "{script}" credentials {project}')
    ini.set(section, "region", region)
    AWS_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    backup = AWS_CONFIG.with_name(AWS_CONFIG.name + ".apm-backup")
    if AWS_CONFIG.exists() and not backup.exists():
        shutil.copy2(AWS_CONFIG, backup)
    with open(AWS_CONFIG, "w") as f:
        ini.write(f)
    return profile_name(project)


def _stable_copy():
    """Profiles call a copy under ~/.apm/bin so they keep working when the plugin updates or moves."""
    me = Path(__file__).resolve()
    if me != STABLE_COPY.resolve():
        if not STABLE_COPY.exists() or STABLE_COPY.read_bytes() != me.read_bytes():
            STABLE_COPY.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(me, STABLE_COPY)
            STABLE_COPY.chmod(0o755)
    return STABLE_COPY


def fetch_credentials(project, refresh=False):
    cache = CACHE / f"{project}.json"
    if not refresh and cache.exists():
        creds = json.loads(cache.read_text())
        expires = datetime.fromisoformat(creds["Expiration"].replace("Z", "+00:00"))
        if (expires - datetime.now(timezone.utc)).total_seconds() > 300:
            return creds
    for attempt in range(4):
        try:
            creds = call("POST", "/api/credentials", {"project": project})
            break
        except ApmError as e:
            if "retry" not in str(e) or attempt == 3:
                raise
            time.sleep(5)
    _private_write(cache, json.dumps(creds))
    return creds


# ---------- CLI ----------

def main(argv=None):
    p = argparse.ArgumentParser(prog="apm", description="Request and use scoped AWS permissions.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("login", help="connect this machine; the owner approves it in the dashboard")
    s.add_argument("--url", help=f"service URL (default {DEFAULT_URL})")
    s.add_argument("--paste", action="store_true", help="paste an API key created in the dashboard instead")
    s = sub.add_parser("projects", help="list projects and their permissions")
    s.add_argument("--search", default="", help="filter, e.g. s3:GetObject or a bucket name")
    s.add_argument("--json", action="store_true")
    s = sub.add_parser("request", help="ask the owner for permissions on a project")
    s.add_argument("--project", required=True)
    s.add_argument("--action", "-a", action="append", required=True, help="IAM action, repeatable")
    s.add_argument("--resource", "-r", action="append", default=[], help="resource ARN, repeatable (default *)")
    s.add_argument("--reason", required=True)
    s.add_argument("--wait", action="store_true", help="block until the owner decides (up to 30 min)")
    s = sub.add_parser("status", help="show requests")
    s.add_argument("id", nargs="?", type=int)
    s.add_argument("--project")
    s = sub.add_parser("wait", help="block until a request is decided")
    s.add_argument("id", type=int)
    s.add_argument("--timeout", type=int, default=1800)
    s = sub.add_parser("use", help="set up AWS profile apm-PROJECT")
    s.add_argument("project")
    s = sub.add_parser("credentials", help="credential_process helper; prints credentials for the AWS CLI/SDKs")
    s.add_argument("project")
    sub.add_parser("mcp", help="run the MCP server on stdio")
    a = p.parse_args(argv)
    try:
        return globals()["cmd_" + a.cmd](a) or 0
    except ApmError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_login(a):
    if a.url:
        _private_write(CLIENT_FILE, json.dumps({"url": a.url.rstrip("/")}) + "\n")
    if a.paste:
        key = getpass.getpass("API key (input hidden): ").strip()
        call("GET", "/api/whoami", key=key)
        _private_write(KEY_FILE, key + "\n")
    else:
        status, code, url = connect(0)
        if status != "connected":
            print(f"Approve this machine in the dashboard (opening {url}). Check the code matches: {code}", flush=True)
            status, code, url = connect(900, open_browser=False)
        if status != "connected":
            raise ApmError(f"connect request {status}; run `apm login` to try again")
    who = call("GET", "/api/whoami")
    print(f"Connected as {who['key']!r} (account {who['account']}). Key saved to {KEY_FILE}.")


def cmd_projects(a):
    items = projects(a.search)
    if a.json:
        print(json.dumps(items, indent=2))
        return
    if not items:
        print("No matching projects." if a.search else "No projects yet. Request access with `apm request`.")
    for item in items:
        print(f"{item['project']}  (use: apm use {item['project']} → --profile {profile_name(item['project'])})")
        for g in item["grants"]:
            print(f"  {g['grant']}: {', '.join(g['actions'])} on {', '.join(g['resources'])}")


def cmd_request(a):
    r = request(a.project, a.action, a.resource, a.reason)
    print(f"Request #{r['id']} sent to the owner for approval.")
    if a.wait:
        return _finish(wait(r["id"], 1800))
    print(f"Check with `apm status {r['id']}` or block with `apm wait {r['id']}`.")


def cmd_status(a):
    rows = [get_request(a.id)] if a.id else call("GET", "/api/requests" + (f"?project={a.project}" if a.project else ""))["requests"]
    if not rows:
        print("No requests.")
    for r in rows:
        line = f"#{r['id']} {r['status']:<9} {r['project']:<16} {', '.join(r['actions'])}"
        if r["resources"] != ["*"]:
            line += f" on {', '.join(r['resources'])}"
        print(line + (f"  ({r['note']})" if r.get("note") else ""))


def cmd_wait(a):
    return _finish(wait(a.id, a.timeout))


def _finish(r):
    if r["status"] == "pending":
        print(f"Request #{r['id']} is still pending.", file=sys.stderr)
        return 3
    print(f"Request #{r['id']} {r['status']}." + (f" Note: {r['note']}" if r.get("note") else ""))
    if r["status"] == "approved":
        print(f"Run `apm use {r['project']}`, then use `aws --profile {profile_name(r['project'])} ...`.")
        return 0
    return 1


def cmd_use(a):
    profile = use(a.project)
    print(f"Profile {profile} is ready: aws --profile {profile} ...  (or AWS_PROFILE={profile})")


def cmd_credentials(a):
    print(json.dumps(fetch_credentials(a.project)))


def cmd_mcp(a):
    McpServer().run()


# ---------- MCP server (JSON-RPC 2.0 over stdio, newline-delimited) ----------

TOOLS = [
    {"name": "connect",
     "description": "Connect this machine to AWS Permissions when other tools say it isn't connected. Opens the "
                    "owner's dashboard in the browser, where they approve this machine; no keys are pasted. "
                    "Tell the user the code it returns so they can check it matches, then call again with "
                    "wait_seconds=120 until connected.",
     "inputSchema": {"type": "object", "properties": {
         "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 120}}}},
    {"name": "list_projects",
     "description": "List AWS projects (permission sets) the owner has approved, with their granted IAM actions and "
                    "resources. Use `search` to find a project that already allows something, e.g. 's3:GetObject', "
                    "a bucket name or a service like 'lambda'.",
     "inputSchema": {"type": "object", "properties": {
         "search": {"type": "string", "description": "Space-separated terms; all must match."}}}},
    {"name": "get_aws_credentials",
     "description": "Get AWS access for a project. Sets up the AWS profile apm-<project>, whose short-lived "
                    "credentials refresh automatically, and returns the profile name. The credentials themselves are "
                    "never shown. Then run AWS CLI/SDK commands with `--profile apm-<project>` or "
                    "`AWS_PROFILE=apm-<project>`.",
     "inputSchema": {"type": "object", "required": ["project"], "properties": {
         "project": {"type": "string"}}}},
    {"name": "request_permissions",
     "description": "Ask the owner to grant IAM permissions to a project; they approve or reject on their phone. "
                    "Request exactly what failed (from the AccessDenied message), with specific resource ARNs where "
                    "possible. A new project name creates that project on approval. IAM, STS AssumeRole, "
                    "Organizations, account, SSO and billing actions can never be granted. Afterwards call "
                    "check_request with wait_seconds to wait for the decision.",
     "inputSchema": {"type": "object", "required": ["project", "actions", "reason"], "properties": {
         "project": {"type": "string", "description": "lowercase letters, digits and dashes, e.g. myapp"},
         "actions": {"type": "array", "items": {"type": "string"}, "description": "IAM actions, e.g. s3:GetObject"},
         "resources": {"type": "array", "items": {"type": "string"}, "description": "Resource ARNs (default *)"},
         "reason": {"type": "string", "description": "Why you need this, shown to the owner"}}}},
    {"name": "check_request",
     "description": "Get the status of a permission request (pending, approved, rejected, revoked). Set "
                    "wait_seconds (max 120) to wait for the owner's decision; call again if still pending.",
     "inputSchema": {"type": "object", "required": ["request_id"], "properties": {
         "request_id": {"type": "integer"},
         "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 120}}}},
    {"name": "list_requests",
     "description": "List recent permission requests, optionally for one project or status.",
     "inputSchema": {"type": "object", "properties": {
         "project": {"type": "string"},
         "status": {"type": "string", "enum": ["pending", "approved", "rejected", "revoked"]}}}},
]
PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]


class McpServer:
    def run(self):
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                self._send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
                continue
            if "id" not in msg or "method" not in msg:
                continue  # notifications and responses need no reply
            try:
                result = self.dispatch(msg["method"], msg.get("params") or {})
                self._send({"jsonrpc": "2.0", "id": msg["id"], "result": result})
            except KeyError:
                self._send({"jsonrpc": "2.0", "id": msg["id"],
                            "error": {"code": -32601, "message": f"unknown method {msg['method']}"}})

    def _send(self, msg):
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    def dispatch(self, method, params):
        if method == "initialize":
            asked = params.get("protocolVersion")
            return {"protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "aws-permissions", "version": VERSION},
                    "instructions": "Use these tools for all AWS access. Find a project with list_projects, then "
                                    "call get_aws_credentials and use the returned AWS profile. On AccessDenied, "
                                    "call request_permissions and wait with check_request."}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": TOOLS}
        if method == "tools/call":
            return self.call_tool(params.get("name"), params.get("arguments") or {})
        raise KeyError(method)

    def call_tool(self, name, args):
        try:
            text = getattr(self, "tool_" + str(name))(**args)
            return {"content": [{"type": "text", "text": text}]}
        except (ApmError, TypeError, ValueError, AttributeError) as e:
            return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}

    def tool_connect(self, wait_seconds=0):
        status, code, url = connect(max(0, min(int(wait_seconds), 120)))
        if status == "connected":
            return "Connected to AWS Permissions. You can use the other tools now."
        if status == "pending":
            return (f"Waiting for the owner to approve this machine at {url} (opened in the browser). Code: {code}. "
                    "Tell the user the code, then call connect again with wait_seconds=120.")
        return f"The connect request was {status}. Ask the user before trying again."

    def tool_list_projects(self, search=""):
        items = projects(search)
        if not items:
            return ("No matching projects. " if search else "No projects yet. ") + \
                   "Use request_permissions to ask the owner for access."
        return json.dumps({"projects": items, "next": "Call get_aws_credentials with a project to use it."}, indent=2)

    def tool_get_aws_credentials(self, project):
        profile = use(project)
        return (f"AWS profile `{profile}` is ready. Run AWS commands with `--profile {profile}` or "
                f"`AWS_PROFILE={profile}`. Credentials refresh automatically and are never displayed. "
                "If a call fails with AccessDenied, use request_permissions.")

    def tool_request_permissions(self, project, actions, reason, resources=None):
        r = request(project, list(actions), list(resources or []), reason)
        return (f"Request #{r['id']} sent to the owner. Call check_request with request_id={r['id']} and "
                "wait_seconds=120 to wait for the decision.")

    def tool_check_request(self, request_id, wait_seconds=0):
        r = wait(request_id, max(0, min(int(wait_seconds), 120)))
        out = {k: r[k] for k in ("id", "project", "status", "actions", "resources", "note")}
        if r["status"] == "approved":
            out["next"] = f"Call get_aws_credentials with project={r['project']!r} (or reuse its profile) and retry."
        elif r["status"] == "pending":
            out["next"] = "Still waiting for the owner. Call check_request again with wait_seconds=120."
        return json.dumps(out, indent=2)

    def tool_list_requests(self, project=None, status=None):
        from urllib.parse import urlencode
        q = urlencode({k: v for k, v in (("project", project), ("status", status)) if v})
        rows = call("GET", "/api/requests" + (f"?{q}" if q else ""))["requests"]
        return json.dumps(rows[:25], indent=2) if rows else "No requests."


if __name__ == "__main__":
    sys.exit(main())
