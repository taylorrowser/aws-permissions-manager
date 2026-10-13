"""Start one loopback-only fixture for manual/cloud-browser recovery QA.
Temporary database is removed on normal exit. Never reads cloud configuration.
"""
import argparse
import json
import tempfile
import time
from pathlib import Path
from broker import Executor,canonical
from server import make_server

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('scenario',choices=['expired-direct','expired-cancel','unknown','approved-cancel']);p.add_argument('--port',type=int,default=0);a=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='permission-broker-qa-') as d:
        server=make_server(Path(d)/'fixture.db',a.port);s=server.store
        now=int(time.time());s.clock=lambda:now-120 if a.scenario!='approved-cancel' else now
        r=s.submit('demo-agent',{'roles':['preview-read','live-inventory-read'],'reason':'Browser QA '+a.scenario,'ttl_seconds':60 if a.scenario!='approved-cancel' else 3600,'task_environment':'preview'})
        s.decide('demo-owner',r['id'],'approve',r['digest'])
        if a.scenario!='approved-cancel':Executor(s).execute(r['id'],True)
        if a.scenario=='unknown':
            with s.tx() as db:db.execute("UPDATE roles SET policy=? WHERE name='preview-read'",(canonical({'unknown':'external-fixture'}),))
        s.clock=time.time
        print(json.dumps({'url':f'http://127.0.0.1:{server.server_port}','scenario':a.scenario,'request_id':r['id'],'simulation_only':True}),flush=True)
        try:server.serve_forever()
        finally:server.server_close()
