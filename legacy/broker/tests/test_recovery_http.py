"""Provider-read-only recovery over the dashboard's exact HTTP actions."""
import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request,urlopen
from broker import Executor,Denied
from server import make_server

class RecoveryHTTPTests(unittest.TestCase):
    def test_expired_unknown_dashboard_api_cancel_reconcile_never_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            server=make_server(Path(directory)/'http.db',0);now=[1800000000];server.store.clock=lambda:now[0]
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            def call(path,token='demo-owner',data=None):
                req=Request(f'http://127.0.0.1:{server.server_port}'+path,data=json.dumps(data).encode() if data is not None else None,headers={'X-Demo-Identity':token,'Content-Type':'application/json'})
                try:
                    with urlopen(req,timeout=3) as r:return r.status,r.read()
                except HTTPError as e:return e.code,e.read()
            try:
                s=server.store;r=s.submit('demo-agent',{'roles':['preview-read','live-inventory-read'],'reason':'Expired recovery HTTP','ttl_seconds':60,'task_environment':'preview'})
                s.decide('demo-owner',r['id'],'approve',r['digest']);Executor(s).execute(r['id'],True);now[0]+=60
                route='/api/requests/'+r['id'];status=json.loads(call(route)[1]);self.assertEqual(status['state'],'expired');self.assertEqual(set(status['available_controls']),{'cancel','reconcile'})
                code,html=call('/');self.assertEqual(code,200);self.assertIn(b'r.available_controls',html);self.assertIn(b'Reconcile provider state (read-only)',html)
                self.assertEqual(call(route+'/reconcile','demo-agent',{'digest':r['digest']})[0],403)
                self.assertEqual(call(route+'/reconcile',data={'digest':'0'*64})[0],403)
                self.assertEqual(call(route+'/control',data={'action':'cancel','digest':r['digest']})[0],200)
                for _ in range(2):
                    code,body=call(route+'/reconcile',data={'digest':r['digest']});self.assertEqual(code,200);self.assertEqual(json.loads(body)['state'],'cancelled')
                self.assertEqual(call(route+'/session','demo-agent',{'role':'preview-read'})[0],403)
                self.assertEqual(call(route+'/execute',data={})[0],403)
                with self.assertRaises(Denied):Executor(s).execute(r['id'])
                with s.tx() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM fake_mutations').fetchone()[0],1)
            finally:server.shutdown();server.server_close();thread.join()

if __name__=='__main__':unittest.main()
