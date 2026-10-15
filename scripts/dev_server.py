"""Run the dashboard locally against in-memory fakes (no AWS, no WorkOS) to try the UI.

    .venv/bin/python scripts/dev_server.py [--port 8765] [--empty]

Open http://localhost:8765/dev/login to sign in as the fake owner. Seeds pending requests of every
risk (some with several grants), enough decided ones to page, a project, an API key and a connect
request unless --empty. Push works for real if the browser supports it: the server generates
throwaway VAPID keys at start-up. The AI reviewer is stubbed: a canned model answers a second after
each new request once a key is saved under Settings (seeded with one unless --empty).
"""
import argparse
import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from apm import policy, push, web  # noqa: E402
from apm.broker import Broker  # noqa: E402
from apm.store import Store  # noqa: E402
from test_apm import FakeCloudFormation, FakeIAM, FakeSTS, FakeTable, fake_reviewer  # noqa: E402

OWNER = "owner@example.com"


def make_app(port, stage):
    private, public = push.generate_vapid_keys()
    settings = web.Settings(f"localhost:{port}", "client_dev", OWNER, public, "dev-session-secret",
                            vapid_private=private, stage=stage)
    settings.origin = f"http://localhost:{port}"
    cfn = FakeCloudFormation()
    app = web.App(settings, Store(FakeTable()), Broker("111122223333", "us-east-1", iam=FakeIAM(), sts=FakeSTS(),
                                                        cloudformation=cfn.client))
    app.cfn = cfn
    app.reviewer = fake_reviewer(canned_review)
    # Queueing runs the review a second later, as the async self-invoke would.
    app.reviewer.lam.invoke = lambda FunctionName, InvocationType, Payload: threading.Timer(
        1, app.review, [json.loads(Payload)["apm_review"]]).start()
    return app


def canned_review(user):
    """A stand-in model: narrow anything broad, note each grant of a request with several."""
    data = json.loads(user.removeprefix("<request>\n").removesuffix("\n</request>"))
    notes = [{"grant": g["grant"], "note": "Scoped to named resources." if g["risk"] in ("Read-only", "Scoped write")
              else "Every resource: ask for the log groups it writes to."} for g in data.get("grants", [])]
    if data["risk"] in ("Broad", "Full access") and not notes:
        if data["actions"] != ["dynamodb:*"]:
            return json.dumps({"verdict": "narrow", "reason": "Far more than the reason needs. Ask for the actions "
                               "and resources the task uses."})
        return json.dumps({"verdict": "narrow", "reason": "dynamodb:* on every resource is far more than the reason "
                           "needs. Creating and describing the import tables would do.",
                           "suggested_actions": ["dynamodb:CreateTable", "dynamodb:DescribeTable"],
                           "suggested_resources": ["arn:aws:dynamodb:us-east-1:111122223333:table/import-*"]})
    return json.dumps({"verdict": "ok", "reason": "Fits the stated purpose and is limited to the resources it names."
                       if not notes else "Two grants are scoped; the logs grant is wider than it needs.",
                       "grant_notes": notes})


def seed(app):
    s = app.store
    s.create_key("macbook")

    def decide(rid, op="approve", hours=0):
        app.decide({"op": op, "id": str(rid), "digest": s.get(rid)["digest"], "hours-1": str(hours)})

    first = s.add("website", ["s3:GetObject", "s3:PutObject"], ["arn:aws:s3:::example-site/*"],
                  "Upload the built site to the bucket.", "macbook")
    decide(first)
    # Same bucket, same time limit: Projects shows both grants on one row.
    decide(s.add("website", ["s3:DeleteObject"], ["arn:aws:s3:::example-site/*"],
                 "Remove pages the new build no longer has.", "macbook"))
    for i in range(12):  # enough history for Decided to page
        rid = s.add("reports", ["athena:StartQueryExecution", "athena:GetQueryResults"], ["*"],
                    f"Run the weekly usage report ({i + 1}).", "macbook")
        decide(rid, "reject" if i % 3 else "approve")
    old = s.add("website", ["sqs:SendMessage"], ["*"], "Queue rebuilds from the CMS webhook.", "macbook")
    decide(old)
    s.t.items[f"req#{old}"]["decided_at"] -= 45 * 86400  # old enough to show as unused on /usage
    now = datetime.now(timezone.utc)
    app.broker.iam.services = [{"ServiceNamespace": "s3", "LastAuthenticated": now - timedelta(hours=6),
                                "TrackedActionsLastAccessed": [
                                    {"ActionName": "GetObject", "LastAccessedTime": now - timedelta(days=3)},
                                    {"ActionName": "PutObject", "LastAccessedTime": now - timedelta(hours=6)},
                                    {"ActionName": "DeleteObject"}]}]
    s.add("website", ["cloudfront:CreateInvalidation"], ["*"],
          "Invalidate the CDN after deploying so visitors see the new pages.", "macbook", suggested_hours=3)
    # Time-limited: Projects shows its countdown, Extend and Revoke early.
    decide(s.add("website", ["logs:FilterLogEvents"], ["arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/site*"],
                 "Read the site function's logs while debugging a failed deploy.", "macbook"), hours=3)
    # Several grants in one request: one pending, one approved with a grant revoked and one time-limited.
    exports = [{"actions": ["s3:GetObject", "s3:ListBucket"],
                "resources": ["arn:aws:s3:::order-exports", "arn:aws:s3:::order-exports/*"], "suggested_hours": 24},
               {"actions": ["dynamodb:PutItem", "dynamodb:UpdateItem"],
                "resources": ["arn:aws:dynamodb:us-east-1:111122223333:table/orders"]},
               {"actions": ["sqs:SendMessage"], "resources": ["arn:aws:sqs:us-east-1:111122223333:order-events"],
                "suggested_hours": 3}]
    rid = s.add("orders", [], [], "Backfill last month's orders from the export bucket and announce each one.",
                "macbook", grants=exports)
    app.decide({"op": "approve", "id": str(rid), "digest": s.get(rid)["digest"], "hours-1": "24", "hours-2": "0",
                "hours-3": "3"})
    app.decide({"op": "revoke", "project": "orders", "sid": f"Req{rid}g3"})
    s.add("data-pipeline", [], [], "Load the nightly import into the warehouse table and archive the input files.",
          "macbook", grants=[{"actions": ["dynamodb:BatchWriteItem", "dynamodb:DescribeTable"],
                              "resources": ["arn:aws:dynamodb:us-east-1:111122223333:table/warehouse"],
                              "suggested_hours": 3},
                             {"actions": ["s3:GetObject", "s3:DeleteObject"],
                              "resources": ["arn:aws:s3:::nightly-import/*"], "suggested_hours": 3},
                             {"actions": ["logs:*"], "resources": ["*"]}])
    s.add("data-pipeline", ["dynamodb:*"], ["*"], "Create and manage tables for the nightly import job.", "macbook")
    s.add("orders", ["dynamodb:PutItem", "dynamodb:UpdateItem"], ["arn:aws:dynamodb:us-east-1:111122223333:table/orders"],
          "Write order status updates from the fulfilment worker.", "macbook")
    s.add("website", ["s3:GetObject", "s3:ListBucket"], ["arn:aws:s3:::example-site", "arn:aws:s3:::example-site/*"],
          "Check which assets are already uploaded before syncing.", "macbook")
    s.add("website", ["s3:PutBucketPolicy"], ["arn:aws:s3:::example-site"],
          "Let CloudFront read the bucket through an origin access control.", "macbook")
    # Size checks: a project whose policy is near IAM's limit. One more is too big to approve; the
    # same grants replacing the old ones fit, and the card lists what they replace.
    media = [f"arn:aws:s3:::media-uploads-{n}/*" for n in range(160)]
    old = s.add("media", ["s3:GetObject"], media, "Serve uploaded media to the transcoder.", "macbook")
    decide(old)
    s.add("media", ["s3:PutObject", "s3:GetObject"], media, "Write transcoded renditions next to each upload.", "macbook")
    s.add("media", ["s3:PutObject", "s3:GetObject"], media, "Write transcoded renditions next to each upload.", "macbook",
          replaces=[f"Req{old}"])
    # Fits only while its grants are permanent: picking a time limit turns Approve off.
    room = policy.MAX_INLINE_POLICY_CHARS - policy.size(policy.grants_document(s.approved("media")))
    thumbs = [f"arn:aws:s3:::media-thumbs-{n}/*" for n in range(room // 31)]
    while policy.size(policy.doc(policy.statement("Req99", ["s3:PutObject"], thumbs))) + 1 > room:
        thumbs.pop()
    s.add("media", ["s3:PutObject"], thumbs, "Write thumbnails for each upload.", "macbook", suggested_hours=3)
    # A stack write approved before its stack had a stored role: Projects shows it blocked.
    decide(s.add("infra", ["cloudformation:UpdateStack"], ["arn:aws:cloudformation:us-east-1:111122223333:stack/web-*/*"],
                 "Update the web stack's parameters.", "macbook"))
    app.cfn.add("us-east-1", "web-prod", "arn:aws:iam::111122223333:role/cdk-exec")
    s.add_connect("codex-cloud", "ab" * 32, "apm_abcdef", "203.0.113.7 apm-client/1.0")
    # AI reviews of most pending requests; website's were asked before the key was saved.
    app.reviewer.save_key("sk-dev-" + "0" * 40)
    for r in s.list(status="pending"):
        if r["project"] != "website":
            app.review(r["id"])


def handler_for(app):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            sys.stderr.write("%s %s\n" % (self.command, self.path))

        def _do(self):
            u = urlparse(self.path)
            jar = SimpleCookie(self.headers.get("Cookie", ""))
            cookies = {k: m.value for k, m in jar.items()}
            if u.path == "/dev/login":
                resp = web.redirect(parse_qs(u.query).get("next", ["/"])[0], [web.cookie(
                    web.SESSION_COOKIE, web.sign(app.s, {"e": OWNER, "x": 4102444800}), 3600)])
            else:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                resp = app(web.Request(self.command, u.path, {k: v[0] for k, v in parse_qs(u.query).items()},
                                       dict(self.headers), cookies, body))
            out = resp.lambda_result()
            data = resp.body if isinstance(resp.body, bytes) else resp.body.encode()
            self.send_response(out["statusCode"])
            for k, v in out["headers"].items():
                if k != "Strict-Transport-Security":
                    self.send_header(k, v)
            for c in out["cookies"]:
                self.send_header("Set-Cookie", c)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        do_GET = do_POST = _do
    return Handler


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--empty", action="store_true", help="start with no data")
    p.add_argument("--stage", default="local", help="APM_STAGE shown in the badge (prod hides it)")
    a = p.parse_args()
    app = make_app(a.port, a.stage)
    if not a.empty:
        seed(app)
    server = ThreadingHTTPServer(("127.0.0.1", a.port), handler_for(app))
    print(json.dumps({"url": f"http://localhost:{a.port}/dev/login"}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
