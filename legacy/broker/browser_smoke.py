"""Optional UI verification. Requires Playwright + Chromium; core demo has no dependencies."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from playwright.sync_api import sync_playwright
from server import make_server

with tempfile.TemporaryDirectory() as directory:
    database=Path(directory)/'browser.sqlite3'
    server=make_server(database,0)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
            page=browser.new_page(viewport={'width':1280,'height':960})
            dialogs=[];errors=[]
            page.on('dialog',lambda d:(dialogs.append(d.message),d.dismiss()))
            page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto(f'http://127.0.0.1:{server.server_port}')
            page.locator('#reason').fill('<img src=x onerror=alert("untrusted reason")> Synthetic Plants read')
            page.get_by_role('button',name='Submit simulated request',exact=True).click()
            page.get_by_text('SIMULATED · awaiting_owner',exact=True).wait_for()
            page.locator('#identity').select_option('demo-owner')
            page.get_by_role('button',name='Approve exact simulated digest',exact=True).click()
            page.get_by_text('SIMULATED · approved',exact=True).wait_for()
            rid=server.store.list_requests('demo-owner')[0]['id']
            subprocess.run([sys.executable,'executor.py','--db',str(database),rid],capture_output=True,check=True)
            page.get_by_role('button',name='Refresh',exact=True).click()
            page.get_by_text('SIMULATED · active',exact=True).wait_for()
            page.locator('#identity').select_option('demo-agent')
            for role in ('preview-read','live-inventory-read'):
                page.get_by_role('button',name='Select simulated '+role,exact=True).click()
                page.wait_for_function('(role) => document.querySelector("#message").textContent.includes(role)',arg=role)
            page.locator('#identity').select_option('demo-owner')
            page.get_by_role('button',name='Revoke simulated effective access',exact=True).wait_for()
            assert not dialogs,dialogs
            assert not errors,errors
            assert page.locator('article img').count()==0
            page.screenshot(path='evidence/dashboard.png',full_page=True)
            browser.close()
            Path('evidence/browser-results.json').write_text(json.dumps({'simulation_only':True,'passed':True,
                'checks':['browser request','owner exact-digest approval','separate executor process','status refresh',
                          'both bundled roles selectable','malicious reason rendered as text','no browser errors'],
                'screenshot':'dashboard.png','session_bodies_saved':False},indent=2)+'\n')
            print('PASS: browser request/approve/execute/status/role selection and untrusted-text rendering')
    finally:
        server.shutdown();server.server_close();thread.join()
