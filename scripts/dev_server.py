"""Run the dashboard locally against in-memory fakes (no AWS, no WorkOS) to try the UI.

    .venv/bin/python scripts/dev_server.py [--port 8765] [--empty]

Open http://localhost:8765/dev/login to sign in as the fake owner. Seeds pending requests of every
risk, enough decided ones to page, a project, an API key and a connect request unless --empty. Push
works for real if the browser supports it: the server generates throwaway VAPID keys at start-up.
"""
import argparse
import json
import sys
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from apm import push, web  # noqa: E402
from apm.broker import Broker  # noqa: E402
from apm.store import Store  # noqa: E402
from test_apm import FakeCloudFormation, FakeIAM, FakeSTS, FakeTable  # noqa: E402

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
    return app


def seed(app):
    s = app.store
    s.create_key("macbook")

    def decide(rid, op="approve", hours=0):
        app.decide({"op": op, "id": str(rid), "digest": s.get(rid)["digest"], "hours-1": str(hours)})

    first = s.add("website", ["s3:GetObject", "s3:PutObject"], ["arn:aws:s3:::example-site/*"],
                  "Upload the built site to the bucket.", "macbook")
    decide(first)
    for i in range(12):  # enough history for Decided to page
        rid = s.add("reports", ["athena:StartQueryExecution", "athena:GetQueryResults"], ["*"],
                    f"Run the weekly usage report ({i + 1}).", "macbook")
        decide(rid, "reject" if i % 3 else "approve")
    s.add("website", ["cloudfront:CreateInvalidation"], ["*"],
          "Invalidate the CDN after deploying so visitors see the new pages.", "macbook", suggested_hours=3)
    # Time-limited: Projects shows its countdown, Extend and Revoke early.
    decide(s.add("website", ["logs:FilterLogEvents"], ["arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/site*"],
                 "Read the site function's logs while debugging a failed deploy.", "macbook"), hours=3)
    s.add("data-pipeline", ["dynamodb:*"], ["*"], "Create and manage tables for the nightly import job.", "macbook")
    s.add("orders", ["dynamodb:PutItem", "dynamodb:UpdateItem"], ["arn:aws:dynamodb:us-east-1:111122223333:table/orders"],
          "Write order status updates from the fulfilment worker.", "macbook")
    s.add("website", ["s3:GetObject", "s3:ListBucket"], ["arn:aws:s3:::example-site", "arn:aws:s3:::example-site/*"],
          "Check which assets are already uploaded before syncing.", "macbook")
    s.add("website", ["s3:PutBucketPolicy"], ["arn:aws:s3:::example-site"],
          "Let CloudFront read the bucket through an origin access control.", "macbook")
    # A stack write approved before its stack had a stored role: Projects shows it blocked.
    decide(s.add("infra", ["cloudformation:UpdateStack"], ["arn:aws:cloudformation:us-east-1:111122223333:stack/web-*/*"],
                 "Update the web stack's parameters.", "macbook"))
    app.cfn.add("us-east-1", "web-prod", "arn:aws:iam::111122223333:role/cdk-exec")
    s.add_connect("codex-cloud", "ab" * 32, "apm_abcdef", "203.0.113.7 apm-client/1.0")


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
