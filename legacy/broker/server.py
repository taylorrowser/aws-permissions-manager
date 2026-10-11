"""Local synthetic request / owner dashboard. No executor HTTP endpoint."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from broker import Store, FakeSTS, Denied, SIMULATION, CATALOG

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Do not record URLs, request bodies, headers, or simulated sessions.
        pass

    def reply(self, code, value, html=False):
        body = value if html else json.dumps(value).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def handle_request(self, post=False):
        try:
            allowed_host = '127.0.0.1:' + str(self.server.server_port)
            if self.headers.get('Host') != allowed_host:
                raise Denied('use the loopback URL printed at startup')
            origin = self.headers.get('Origin')
            if origin is not None and origin != 'http://' + allowed_host:
                raise Denied('cross-origin requests denied')
            path = urlsplit(self.path).path
            token = self.headers.get('X-Demo-Identity', '')
            s = self.server.store
            if not post and path == '/':
                return self.reply(200, Path(__file__).with_name('dashboard.html').read_bytes(), True)
            if not post and path == '/api/catalog':
                return self.reply(200, {'simulation': SIMULATION, 'roles': CATALOG})
            if not post and path == '/api/requests':
                return self.reply(200, {'simulation': SIMULATION, 'requests': s.list_requests(token)})
            if not post and path.startswith('/api/requests/'):
                return self.reply(200, s.status(token, path.split('/')[-1]))
            if not post:
                return self.reply(404, {'simulation': SIMULATION, 'error': 'not found'})
            if self.headers.get('Content-Type') != 'application/json':
                raise Denied('application/json required')
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 16384:
                raise Denied('body must be 1–16384 bytes')
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise Denied('object required')
            if path == '/api/requests':
                return self.reply(201, s.submit(token, data))
            parts = path.strip('/').split('/')
            if len(parts) != 4 or parts[:2] != ['api', 'requests']:
                return self.reply(404, {'simulation': SIMULATION, 'error': 'not found; no executor HTTP route'})
            rid, action = parts[2:]
            if action == 'decision' and set(data) == {'choice', 'digest'}:
                result = s.decide(token, rid, data['choice'], data['digest'])
            elif action == 'control' and set(data) == {'action', 'digest'}:
                result = s.control(token, rid, data['action'], data['digest'])
            elif action == 'reconcile' and set(data) == {'digest'}:
                result = s.reconcile(token, rid, data['digest'])
            elif action == 'session' and set(data) == {'role'}:
                result = FakeSTS(s).vend(token, rid, data['role'])
            else:
                raise Denied('unknown operation or extra fields')
            return self.reply(200, result)
        except Denied as e:
            self.reply(403, {'simulation': SIMULATION, 'error': str(e)})
        except (ValueError, TypeError, KeyError):
            self.reply(400, {'simulation': SIMULATION, 'error': 'invalid request'})

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request(True)


def make_server(db_path, port):
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.store = Store(db_path)
    return server

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='SIMULATED permission broker — local only')
    p.add_argument('--db', default='demo.sqlite3')
    p.add_argument('--port', type=int, default=8765)
    a = p.parse_args()
    server = make_server(a.db, a.port)
    print(f'{SIMULATION}\nOpen http://127.0.0.1:{server.server_port}', flush=True)
    server.serve_forever()
