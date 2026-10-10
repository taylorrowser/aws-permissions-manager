"""Optional rendered recovery verification, runnable where Chromium is supported.
No live integration. Never exposes the server beyond loopback or stores sessions.
"""
import json
import tempfile
import threading
from pathlib import Path
from playwright.sync_api import sync_playwright
from broker import Executor,Denied,canonical
from server import make_server

def run_scenario(browser,scenario):
    with tempfile.TemporaryDirectory(prefix='broker-browser-recovery-') as directory:
        server=make_server(Path(directory)/'fixture.db',0);now=[1800000000];s=server.store;s.clock=lambda:now[0]
        r=s.submit('demo-agent',{'roles':['preview-read','live-inventory-read'],'reason':'Browser recovery '+scenario,'ttl_seconds':60,'task_environment':'preview'})
        s.decide('demo-owner',r['id'],'approve',r['digest'])
        if scenario!='approved-cancel':Executor(s).execute(r['id'],True);now[0]+=60
        if scenario=='unknown':
            with s.tx() as db:db.execute("UPDATE roles SET policy=? WHERE name='preview-read'",(canonical({'unknown':'external-fixture'}),))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();page=browser.new_page()
        errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        try:
            page.goto(f'http://127.0.0.1:{server.server_port}');page.locator('#identity').select_option('demo-owner')
            if scenario in ('expired-cancel','approved-cancel'):
                page.get_by_role('button',name='Cancel simulated grant',exact=True).click()
                page.get_by_text('SIMULATED · cancelled',exact=True).wait_for()
            if scenario!='approved-cancel':
                page.get_by_role('button',name='Reconcile provider state (read-only)',exact=True).click()
                expected='needs_review' if scenario=='unknown' else 'cancelled' if scenario=='expired-cancel' else 'expired'
                page.get_by_text('SIMULATED · '+expected,exact=True).wait_for()
                if scenario=='unknown':
                    page.get_by_role('button',name='Cancel simulated grant',exact=True).click()
                    page.get_by_text('SIMULATED · cancelled',exact=True).wait_for()
                    page.get_by_role('button',name='Reconcile provider state (read-only)',exact=True).click()
                    page.get_by_text('SIMULATED · cancelled',exact=True).wait_for()
                    assert s.status('demo-owner',r['id'])['recovery_required']
            page.get_by_role('button',name='Refresh',exact=True).click();page.reload()
            page.locator('#identity').select_option('demo-owner')
            with s.tx() as db:count=db.execute('SELECT COUNT(*) FROM fake_mutations').fetchone()[0]
            assert count==(0 if scenario=='approved-cancel' else 1)
            try:Executor(s).execute(r['id'])
            except Denied:pass
            else:raise AssertionError('later execution was allowed')
            assert not errors,errors
            return {'scenario':scenario,'passed':True,'provider_writes':count,'later_apply_denied':True,'browser_errors':errors}
        finally:page.close();server.shutdown();server.server_close();thread.join()

if __name__=='__main__':
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
        try:results=[run_scenario(browser,s) for s in ['expired-direct','expired-cancel','unknown','approved-cancel']]
        finally:browser.close()
    Path('evidence').mkdir(exist_ok=True)
    Path('evidence/browser-recovery-results.json').write_text(json.dumps({'simulation_only':True,'passed':True,'checks':results,'session_bodies_saved':False},indent=2)+'\n')
    print('PASS: rendered expired, cancelled, unknown and approved recovery scenarios')
