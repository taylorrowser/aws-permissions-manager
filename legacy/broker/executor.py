"""Separate fake privileged executor process; never exposed as an HTTP route."""
import argparse
import json
from broker import Store, Executor, Denied

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='SIMULATED permission executor (no AWS)')
    p.add_argument('--db', default='demo.sqlite3')
    p.add_argument('request_id')
    p.add_argument('--simulate-timeout-after-write', action='store_true')
    a = p.parse_args()
    try:
        print(json.dumps(Executor(Store(a.db)).execute(a.request_id, a.simulate_timeout_after_write), indent=2))
    except Denied as e:
        p.exit(1, 'SIMULATED executor refused: ' + str(e) + '\n')
