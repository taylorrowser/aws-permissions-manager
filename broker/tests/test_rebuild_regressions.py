"""Fresh regressions for the five post-archive correction areas."""
import json
import tempfile
import unittest
from pathlib import Path
from broker import Store, Executor, FakeSTS, Denied, CATALOG, canonical

class RebuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'test.db'
        self.now=1800000000; self.s=Store(self.path,lambda:self.now); self.e=Executor(self.s); self.sts=FakeSTS(self.s)
    def tearDown(self):self.tmp.cleanup()
    def approved(self,roles=None,ttl=60):
        r=self.s.submit('demo-agent',{'roles':roles or list(CATALOG),'reason':'Rebuild regression','ttl_seconds':ttl,'task_environment':'preview'})
        self.s.decide('demo-owner',r['id'],'approve',r['digest']);return r
    def count(self,table='fake_mutations'):
        with self.s.tx() as db:return db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
    def cancel(self,r):return self.s.control('demo-owner',r['id'],'cancel',r['digest'])
    def reconcile(self,r):return self.s.reconcile('demo-owner',r['id'],r['digest'])
    def test_cancel_approved_prevents_later_execution_or_issuance(self):
        r=self.approved();self.assertEqual(self.cancel(r)['state'],'cancelled')
        for fn in [lambda:self.e.execute(r['id']),lambda:self.sts.vend('demo-agent',r['id'],'preview-read')]:
            with self.assertRaises(Denied):fn()
        self.assertEqual(self.count(),0)
    def test_retry_of_uncertain_write_is_read_only_before_explicit_resume(self):
        r=self.approved();self.e.execute(r['id'],True)
        self.assertEqual(self.e.execute(r['id'])['state'],'ready_to_resume');self.assertEqual(self.count(),1)
        self.assertEqual(self.e.execute(r['id'])['state'],'active');self.assertEqual(self.count(),2)
    def test_cancel_uncertain_then_reconcile_is_read_only_and_terminal(self):
        r=self.approved();self.e.execute(r['id'],True);self.cancel(r)
        self.assertTrue(self.s.status('demo-owner',r['id'])['recovery_required'])
        self.assertEqual(self.reconcile(r)['state'],'cancelled');self.assertEqual(self.count(),1)
        with self.assertRaises(Denied):self.e.execute(r['id'])
    def test_overlapping_grant_cannot_overwrite_active_policy_or_session(self):
        first=self.approved(['preview-read']);self.e.execute(first['id']);session=self.sts.vend('demo-agent',first['id'],'preview-read')
        self.now+=1;second=self.approved(['preview-read'],ttl=120)
        self.assertEqual(self.e.execute(second['id'])['state'],'blocked_overlap');self.assertEqual(self.count(),1)
        self.sts.read('demo-agent',session['session_id'],'sim://preview/devices')
    def test_disjoint_grants_coexist(self):
        for role in CATALOG:
            r=self.approved([role]);self.assertEqual(self.e.execute(r['id'])['state'],'active');self.sts.vend('demo-agent',r['id'],role)
        self.assertEqual(self.count(),2)
    def test_expired_uncertain_retains_recovery_controls_and_read_only_reconcile(self):
        r=self.approved();self.e.execute(r['id'],True);self.now+=60
        status=self.s.status('demo-owner',r['id']);self.assertTrue(status['recovery_required']);self.assertIn('reconcile',status['available_controls']);self.assertIn('cancel',status['available_controls'])
        self.reconcile(r);self.assertEqual(self.count(),1)
        with self.assertRaises(Denied):self.e.execute(r['id'])
    def test_expired_uncertain_cancel_then_reconcile_is_read_only(self):
        r=self.approved();self.e.execute(r['id'],True);self.now+=60;self.cancel(r);self.reconcile(r)
        self.assertEqual(self.count(),1)
        with self.assertRaises(Denied):self.e.execute(r['id'])
    def test_cancel_blocked_overlap_never_reserves_untouched_role(self):
        first=self.approved(['preview-read']);self.e.execute(first['id'])
        blocked=self.approved();self.assertEqual(self.e.execute(blocked['id'])['state'],'blocked_overlap');self.cancel(blocked)
        other=self.approved(['live-inventory-read']);self.assertEqual(self.e.execute(other['id'])['state'],'active')
        with self.s.tx() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM reservations WHERE request_id=?',(blocked['id'],)).fetchone()[0],0)
    def test_persisted_legacy_phantom_reservation_removed_without_attempt_evidence(self):
        blocked=self.approved()
        with self.s.tx() as db:
            db.execute("UPDATE requests SET state='cancelled' WHERE id=?",(blocked['id'],))
            db.execute('INSERT INTO reservations(role,request_id) VALUES (?,?)',('preview-read',blocked['id']))
        reopened=Store(self.path,lambda:self.now);fresh=self.approved(['preview-read'])
        self.assertEqual(Executor(reopened).execute(fresh['id'])['state'],'active')
    def test_legacy_unknown_attempt_without_reservation_stays_quarantined_after_cutoff(self):
        r=self.approved(['preview-read']);self.e.execute(r['id'],True)
        with self.s.tx() as db:
            db.execute("UPDATE roles SET policy=? WHERE name='preview-read'",(canonical({'unknown':'external'}),))
            db.execute("UPDATE requests SET state='needs_review' WHERE id=?",(r['id'],))
            db.execute('DELETE FROM reservations');db.execute('DELETE FROM execution_attempts')
        self.now+=60;reopened=Store(self.path,lambda:self.now);new=self.approved(['preview-read'])
        self.assertEqual(Executor(reopened).execute(new['id'])['state'],'blocked_overlap');self.assertEqual(self.count(),1)
        self.assertTrue(reopened.status('demo-owner',r['id'])['recovery_required'])
    def test_known_revoked_reservation_until_cutoff_and_old_session_never_revives(self):
        r=self.approved(['preview-read']);self.e.execute(r['id']);sid=self.sts.vend('demo-agent',r['id'],'preview-read')['session_id']
        self.s.control('demo-owner',r['id'],'revoke',r['digest']);next_r=self.approved(['preview-read'],ttl=120)
        self.assertEqual(self.e.execute(next_r['id'])['state'],'blocked_overlap');self.now+=60
        self.assertEqual(self.e.execute(next_r['id'])['state'],'active')
        with self.assertRaises(Denied):self.sts.read('demo-agent',sid,'sim://preview/devices')
    def test_known_cancelled_reservation_until_cutoff(self):
        r=self.approved(['preview-read']);self.e.execute(r['id']);self.cancel(r);next_r=self.approved(['preview-read'],ttl=120)
        self.assertEqual(self.e.execute(next_r['id'])['state'],'blocked_overlap');self.now+=60
        self.assertEqual(self.e.execute(next_r['id'])['state'],'active')
    def test_unknown_reconciliation_never_overwrites_or_releases_quarantine(self):
        r=self.approved();self.e.execute(r['id'],True)
        with self.s.tx() as db:db.execute("UPDATE roles SET policy=? WHERE name='preview-read'",(canonical({'unknown':'external'}),))
        self.assertEqual(self.reconcile(r)['state'],'needs_review');self.assertEqual(self.count(),1)
        self.cancel(r);self.now+=60;self.reconcile(r);new=self.approved(['preview-read'])
        self.assertEqual(self.e.execute(new['id'])['state'],'blocked_overlap');self.assertEqual(self.count(),1)
    def test_active_policy_drift_is_visible_as_needs_review(self):
        r=self.approved();self.e.execute(r['id'])
        with self.s.tx() as db:db.execute("UPDATE roles SET policy=? WHERE name='preview-read'",(canonical({'drift':True}),))
        status=self.s.status('demo-owner',r['id']);self.assertEqual(status['state'],'needs_review');self.assertTrue(status['recovery_required'])
    def test_completed_receipt_reverted_to_baseline_is_not_falsely_resumable(self):
        r=self.approved(['preview-read']);self.e.execute(r['id'])
        with self.s.tx() as db:db.execute("UPDATE roles SET policy='{}' WHERE name='preview-read'")
        self.assertEqual(self.s.status('demo-owner',r['id'])['state'],'needs_review')
        self.assertEqual(self.reconcile(r)['state'],'needs_review')
        self.assertTrue(self.s.status('demo-owner',r['id'])['recovery_required'])
        with self.assertRaises(Denied):self.e.execute(r['id'])
        self.assertEqual(self.count(),1)
    def test_stopped_issuance_intent_survives_drift_and_reconciliation(self):
        r=self.approved(['preview-read']);self.e.execute(r['id'])
        self.s.control('demo-owner',r['id'],'stop_issuance',r['digest'])
        with self.s.tx() as db:db.execute("UPDATE roles SET policy=? WHERE name='preview-read'",(canonical({'drift':True}),))
        self.assertEqual(self.s.status('demo-owner',r['id'])['state'],'needs_review')
        with self.s.tx() as db:db.execute("UPDATE roles SET policy=? WHERE name='preview-read'",(canonical(r['manifest']['targets']['preview-read']['desired_policy']),))
        self.assertEqual(self.reconcile(r)['state'],'issuance_stopped')
        with self.assertRaises(Denied):self.sts.vend('demo-agent',r['id'],'preview-read')
    def test_drift_first_observed_after_cutoff_is_quarantined_before_release(self):
        r=self.approved(['preview-read']);self.e.execute(r['id'])
        with self.s.tx() as db:db.execute("UPDATE roles SET policy=? WHERE name='preview-read'",(canonical({'unknown':'external'}),))
        self.now+=60;new=self.approved(['preview-read'])
        self.assertEqual(self.e.execute(new['id'])['state'],'blocked_overlap')
        self.assertTrue(self.s.status('demo-owner',r['id'])['recovery_required']);self.assertEqual(self.count(),1)
    def test_safe_cutoff_release_does_not_quarantine_old_grant_after_successor_write(self):
        old=self.approved(['preview-read']);self.e.execute(old['id']);sid=self.sts.vend('demo-agent',old['id'],'preview-read')['session_id']
        self.now+=60;new=self.approved(['preview-read']);self.assertEqual(self.e.execute(new['id'])['state'],'active')
        self.s.status('demo-owner',old['id']);self.assertEqual(self.s.status('demo-owner',new['id'])['state'],'active')
        with self.s.tx() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM reservations WHERE request_id=?',(old['id'],)).fetchone()[0],0)
        with self.assertRaises(Denied):self.sts.read('demo-agent',sid,'sim://preview/devices')
    def test_cancel_and_reconcile_require_owner_and_exact_digest(self):
        r=self.approved();self.e.execute(r['id'],True)
        for token,d in [('demo-agent',r['digest']),('forged-owner',r['digest']),('demo-owner','0'*64)]:
            with self.assertRaises(Denied):self.s.control(token,r['id'],'cancel',d)
            with self.assertRaises(Denied):self.s.reconcile(token,r['id'],d)
        self.assertEqual(self.count(),1)

if __name__=='__main__':unittest.main()
