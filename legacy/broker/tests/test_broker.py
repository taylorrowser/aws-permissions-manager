import contextlib
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from broker import Store, Executor, FakeSTS, Denied, canonical, digest, CATALOG
from server import make_server

class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'test.sqlite3'
        self.now = 1_800_000_000
        self.store = Store(self.path, lambda: self.now)
        self.executor = Executor(self.store)
        self.sts = FakeSTS(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, roles=None, ttl=3600, **extra):
        return self.store.submit('demo-agent', {'roles': roles or list(CATALOG),
            'reason': 'Read synthetic Plants inventory', 'ttl_seconds': ttl,
            'task_environment': 'preview', **extra})

    def approved(self, **kw):
        r = self.request(**kw)
        self.store.decide('demo-owner', r['id'], 'approve', r['digest'])
        return r

    def active(self, **kw):
        r = self.approved(**kw)
        self.assertEqual(self.executor.execute(r['id'])['state'], 'active')
        return r

    def count(self, table):
        with self.store.tx() as db:
            return db.execute('SELECT count(*) FROM ' + table).fetchone()[0]

    def test_all_bundle_roles_selectable_including_live_from_preview(self):
        r = self.active()
        self.assertEqual(r['manifest']['task_environment'], 'preview')
        self.assertEqual(r['manifest']['audience'], 'agent-preview')
        self.assertEqual(r['digest'], digest(r['manifest']))
        for role in CATALOG:
            self.assertEqual(r['manifest']['targets'][role]['role_id'], CATALOG[role]['role_id'])
            session = self.sts.vend('demo-agent', r['id'], role)
            read = self.sts.read('demo-agent', session['session_id'], CATALOG[role]['resources'][0])
            self.assertEqual(read['items'][0]['project'], 'plants')

    def test_self_approval_and_forged_owner_zero_mutations(self):
        r = self.request()
        for token in ('demo-agent', 'demo-other-agent', 'owner-alice', 'forged-owner'):
            with self.assertRaises(Denied):
                self.store.decide(token, r['id'], 'approve', r['digest'])
        with self.assertRaises(Denied):
            self.executor.execute(r['id'])
        self.assertEqual(self.count('decisions'), 0)
        self.assertEqual(self.count('fake_mutations'), 0)

    def test_forged_decision_record_rejected(self):
        r = self.request()
        with self.store.tx() as db:
            db.execute('INSERT INTO decisions VALUES (?,?,?,?,?)', (r['id'],r['digest'],'agent-preview','approve',self.now))
            db.execute("UPDATE requests SET state='approved' WHERE id=?", (r['id'],))
        with self.assertRaises(Denied):
            self.executor.execute(r['id'])
        self.assertEqual(self.count('fake_mutations'), 0)

    def test_forged_claims_wildcards_and_policy_paths_zero_mutations(self):
        for extra in ({'audience':'owner-alice'}, {'owner':'owner-alice'}, {'project':'other'},
                      {'policy': {'Action':'*'}}, {'roles':['*']}, {'roles':['iam:PassRole']},
                      {'roles':['sts:AssumeRole']}, {'roles':['administrator']}):
            with self.assertRaises(Denied):
                self.request(**extra)
        self.assertEqual(self.count('fake_mutations'), 0)

    def test_digest_change_and_post_approval_edit_zero_mutations(self):
        r = self.request()
        with self.assertRaises(Denied):
            self.store.decide('demo-owner', r['id'], 'approve', '0'*64)
        self.store.decide('demo-owner', r['id'], 'approve', r['digest'])
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.tx() as db:
                db.execute('UPDATE requests SET manifest=? WHERE id=?', ('{}', r['id']))
        # Corrupt-storage fixture bypasses trigger to prove executor digest recheck.
        with self.store.tx() as db:
            db.execute('DROP TRIGGER frozen_request')
            changed = r['manifest']; changed['reason'] = 'edited after approval'
            db.execute('UPDATE requests SET manifest=? WHERE id=?', (canonical(changed),r['id']))
        with self.assertRaises(Denied):
            self.executor.execute(r['id'])
        self.assertEqual(self.count('fake_mutations'), 0)

    def test_rehashed_wildcard_manifest_still_denied(self):
        r = self.request()
        m = r['manifest']; m['targets']['preview-read']['desired_policy']['actions'] = ['*']
        with self.store.tx() as db:
            db.execute('DROP TRIGGER frozen_request')
            db.execute('UPDATE requests SET manifest=?,digest=? WHERE id=?', (canonical(m),digest(m),r['id']))
        with self.assertRaises(Denied):
            self.store.decide('demo-owner', r['id'], 'approve', digest(m))
        with self.assertRaises(Denied):
            self.executor.execute(r['id'])
        self.assertEqual(self.count('fake_mutations'), 0)

    def test_out_of_bundle_role_and_wrong_audience_no_extra_mutations(self):
        r = self.active(roles=['preview-read'])
        before = self.count('fake_mutations')
        with self.assertRaises(Denied):
            self.sts.vend('demo-agent',r['id'],'live-inventory-read')
        with self.assertRaises(Denied):
            self.sts.vend('demo-other-agent',r['id'],'preview-read')
        with self.assertRaises(Denied):
            self.store.status('demo-other-agent',r['id'])
        self.assertEqual(self.count('fake_mutations'), before)

    def test_100_replays_one_logical_grant(self):
        r = self.approved()
        results = [self.executor.execute(r['id']) for _ in range(100)]
        self.assertEqual(sum(not x['duplicate'] for x in results),1)
        self.assertEqual(len({x['operation_id'] for x in results}),1)
        self.assertEqual(self.count('receipts'),1)
        self.assertEqual(self.count('fake_mutations'),len(CATALOG))

    def test_concurrent_duplicate_delivery(self):
        r = self.approved()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: Executor(Store(self.path,lambda:self.now)).execute(r['id']),range(20)))
        self.assertEqual(sum(not x['duplicate'] for x in results),1)
        self.assertEqual(self.count('fake_mutations'),len(CATALOG))

    def test_timeout_after_fake_put_reconciles_after_restart(self):
        r = self.approved()
        first = self.executor.execute(r['id'],timeout_after_write=True)
        self.assertEqual(first['state'],'reconciling')
        self.assertEqual(self.count('fake_mutations'),1)
        self.assertEqual(self.count('receipts'),0)
        with self.assertRaises(Denied):
            self.sts.vend('demo-agent',r['id'],'live-inventory-read')
        restarted = Executor(Store(self.path,lambda:self.now))
        result = restarted.execute(r['id'])
        self.assertEqual(result['state'],'ready_to_resume')
        self.assertEqual(self.count('fake_mutations'),1)
        result = restarted.execute(r['id'])
        self.assertEqual(result['state'],'active')
        self.assertEqual(self.count('fake_mutations'),len(CATALOG))
        self.assertEqual(self.count('receipts'),1)

    def test_timeout_then_unknown_state_not_overwritten(self):
        r = self.approved()
        self.executor.execute(r['id'],True)
        with self.store.tx() as db:
            db.execute("UPDATE roles SET policy=? WHERE name='live-inventory-read'",(canonical({'unknown':'external-state'}),))
        result = self.executor.execute(r['id'])
        self.assertEqual(result['state'],'needs_review')
        self.assertEqual(self.count('fake_mutations'),1)
        with self.store.tx() as db:
            self.assertEqual(json.loads(db.execute("SELECT policy FROM roles WHERE name='live-inventory-read'").fetchone()[0]),{'unknown':'external-state'})

    def test_changed_baseline_requires_fresh_review(self):
        r = self.approved()
        with self.store.tx() as db:
            db.execute("UPDATE roles SET policy=? WHERE name='preview-read'",(canonical({'drift':True}),))
        self.assertEqual(self.executor.execute(r['id'])['state'],'needs_review')
        self.assertEqual(self.count('fake_mutations'),0)
        with self.assertRaises(Denied):
            self.store.decide('demo-owner',r['id'],'approve',r['digest'])
        fresh = self.approved()
        self.assertNotEqual(r['digest'],fresh['digest'])
        self.assertEqual(self.executor.execute(fresh['id'])['state'],'active')

    def test_recreated_role_requires_review_before_apply_and_vending(self):
        r = self.approved()
        with self.store.tx() as db:
            db.execute("UPDATE roles SET role_id='SIM-RECREATED' WHERE name='preview-read'")
        self.assertEqual(self.executor.execute(r['id'])['state'],'needs_review')
        self.assertEqual(self.count('fake_mutations'),0)
        with self.assertRaises(Denied):
            self.sts.vend('demo-agent',r['id'],'preview-read')
        with self.assertRaises(Denied):
            self.request()

    def test_role_recreated_after_activation_denies_existing_session(self):
        r = self.active()
        session = self.sts.vend('demo-agent',r['id'],'preview-read')
        with self.store.tx() as db:
            db.execute("UPDATE roles SET role_id='SIM-RECREATED' WHERE name='preview-read'")
        for call in (lambda:self.sts.vend('demo-agent',r['id'],'preview-read'),
                     lambda:self.sts.read('demo-agent',session['session_id'],'sim://preview/devices')):
            with self.assertRaises(Denied): call()
        self.assertEqual(self.store.status('demo-owner',r['id'])['state'],'needs_review')
        with self.assertRaises(Denied):self.executor.execute(r['id'])
        self.assertEqual(self.count('fake_mutations'),len(CATALOG))

    def test_expiry_exact_cutoff_without_cleanup(self):
        r = self.active(ttl=60)
        session = self.sts.vend('demo-agent',r['id'],'preview-read')
        self.now += 59
        self.sts.read('demo-agent',session['session_id'],'sim://preview/devices')
        self.now += 1  # No scheduler or cleanup invoked.
        for call in (lambda:self.sts.read('demo-agent',session['session_id'],'sim://preview/devices'),
                     lambda:self.sts.vend('demo-agent',r['id'],'preview-read'),
                     lambda:self.executor.execute(r['id'])):
            with self.assertRaises(Denied): call()
        self.assertEqual(self.store.status('demo-agent',r['id'])['state'],'expired')
        with self.store.tx() as db:
            self.assertNotEqual(db.execute("SELECT policy FROM roles WHERE name='preview-read'").fetchone()[0],'{}')

    def test_expired_pending_cannot_approve(self):
        r = self.request(ttl=1); self.now += 1
        with self.assertRaises(Denied):
            self.store.decide('demo-owner',r['id'],'approve',r['digest'])
        self.assertEqual(self.count('fake_mutations'),0)

    def test_rejection_is_terminal_and_cannot_vend(self):
        r = self.request()
        self.store.decide('demo-owner',r['id'],'reject',r['digest'])
        for call in (lambda:self.executor.execute(r['id']),
                     lambda:self.sts.vend('demo-agent',r['id'],'preview-read'),
                     lambda:self.store.decide('demo-owner',r['id'],'approve',r['digest'])):
            with self.assertRaises(Denied): call()
        self.assertEqual(self.count('fake_mutations'),0)

    def test_stop_issuance_distinct_from_effective_revocation(self):
        r = self.active()
        session = self.sts.vend('demo-agent',r['id'],'preview-read')
        self.store.control('demo-owner',r['id'],'stop_issuance',r['digest'])
        with self.assertRaises(Denied): self.sts.vend('demo-agent',r['id'],'preview-read')
        self.sts.read('demo-agent',session['session_id'],'sim://preview/devices')
        self.store.control('demo-owner',r['id'],'revoke',r['digest'])
        for call in (lambda:self.sts.read('demo-agent',session['session_id'],'sim://preview/devices'),
                     lambda:self.sts.vend('demo-agent',r['id'],'preview-read'),
                     lambda:self.executor.execute(r['id'])):
            with self.assertRaises(Denied): call()
        self.assertEqual(self.store.status('demo-owner',r['id'])['state'],'revoked')

    def test_effective_cutoff_independent_of_session_expiry(self):
        r = self.active(ttl=60)
        session = self.sts.vend('demo-agent',r['id'],'preview-read')
        # Artificially extend session lifetime: grant cutoff must independently deny.
        with self.store.tx() as db:
            db.execute('UPDATE sessions SET expires=?',(self.now+900,))
        self.now += 60
        with self.assertRaises(Denied): self.sts.read('demo-agent',session['session_id'],'sim://preview/devices')

    def test_project_and_resource_scope(self):
        r = self.active(); session=self.sts.vend('demo-agent',r['id'],'preview-read')
        for resource,project in [('sim://live/devices','plants'),('sim://preview/devices','other'),('sim://preview/secrets','plants')]:
            with self.assertRaises(Denied): self.sts.read('demo-agent',session['session_id'],resource,project)

    def test_persistent_journal_and_no_credential_body_in_logs_or_evidence(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output),contextlib.redirect_stderr(output):
            r=self.active(); session=self.sts.vend('demo-agent',r['id'],'preview-read')
        restarted=Store(self.path,lambda:self.now)
        journal=restarted.status('demo-owner',r['id'])['journal']
        self.assertEqual([x['event'] for x in journal],['submitted','approve','applying','active','simulated_session_issued'])
        evidence=canonical(journal)+output.getvalue()
        self.assertNotIn(session['session_id'],evidence)
        for field in ('SecretAccessKey','AccessKeyId','SessionToken'):
            self.assertNotIn(field,canonical(session))
        self.assertEqual(session['credentials'],'NONE — synthetic session only')
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.tx() as db: db.execute('DELETE FROM journal')

class HTTPTests(unittest.TestCase):
    def test_http_request_owner_executor_status_and_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'http.sqlite3'
            server=make_server(path,0)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            origin=f'http://127.0.0.1:{server.server_port}'
            def call(route,token='demo-agent',data=None,headers=None):
                req=Request(origin+route,data=json.dumps(data).encode() if data is not None else None,
                            headers={'X-Demo-Identity':token,'Content-Type':'application/json',**(headers or {})})
                try:
                    with urlopen(req,timeout=5) as response:return response.status,response.read()
                except HTTPError as error:return error.code,error.read()
            try:
                code,html=call('/');self.assertEqual(code,200);self.assertIn(b'SIMULATED ONLY',html)
                payload={'roles':['preview-read','live-inventory-read'],'reason':'<img src=x onerror=alert(1)>','ttl_seconds':3600,'task_environment':'preview'}
                code,body=call('/api/requests',data=payload);self.assertEqual(code,201);r=json.loads(body)
                decision={'choice':'approve','digest':r['digest']}
                route='/api/requests/'+r['id']
                self.assertEqual(call(route+'/decision',data=decision)[0],403)
                self.assertEqual(call(route+'/decision','forged-owner',decision)[0],403)
                self.assertEqual(call(route+'/decision','demo-owner',{**decision,'owner':'owner-alice'})[0],403)
                self.assertEqual(call(route+'/decision','demo-owner',decision,{'Origin':'https://foreign.invalid'})[0],403)
                self.assertEqual(call(route+'/decision','demo-owner',decision)[0],200)
                self.assertEqual(call(route+'/execute','demo-owner',{})[0],403)
                run=subprocess.run([sys.executable,'executor.py','--db',str(path),r['id']],capture_output=True,text=True,check=True)
                self.assertEqual(json.loads(run.stdout)['state'],'active')
                self.assertEqual(json.loads(call(route)[1])['state'],'active')
                self.assertEqual(call(route+'/session',data={'role':'live-inventory-read'})[0],200)
                self.assertEqual(call(route+'/session',data={'role':'administrator'})[0],403)
                r2=json.loads(call('/api/requests',data=payload)[1]);route2='/api/requests/'+r2['id']
                self.assertEqual(call(route2+'/decision','demo-owner',{'choice':'reject','digest':r2['digest']})[0],200)
                self.assertEqual(json.loads(call(route2)[1])['state'],'rejected')
                self.assertEqual(call(route2+'/session',data={'role':'preview-read'})[0],403)
                self.assertIn(b'e.textContent=value',html)
                self.assertNotIn(b'innerHTML',html)
            finally:
                server.shutdown();server.server_close();thread.join()

if __name__=='__main__':unittest.main()
