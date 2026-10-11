import unittest,tempfile,json,re,sqlite3
from fastapi.testclient import TestClient
from integration.http import create_app,HTTPConfig
from integration.fixtures import *
from integration.contracts import *

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.origin='http://127.0.0.1:8877'
        self.s,self.b,self.browser=make_fixture(self.tmp.name+'/s.db',origin=self.origin)
        self.client=TestClient(create_app(self.s,self.b,self.browser,HTTPConfig(origin=self.origin,offline_mode=True)),base_url=self.origin); self.client.__enter__()
        self.headers={'Authorization':'Bearer OFFLINE-ONLY'}
    def tearDown(self): self.client.__exit__(None,None,None);self.tmp.cleanup()
    def request(self):
        data={'logical_role':'existing-ec2','expected_generation':0,'scope':{'actions':['ec2:DescribeInstances'],'instance_arns':[]},'access':'ongoing','reason':'Inspect the instance status','idempotency_key':'request-0001'}
        r=self.client.post('/v1/requests',headers=self.headers,json=data);self.assertEqual(r.status_code,200,r.text);return r.json()
    def form(self,rid):
        self.client.get('/offline/login')
        r=self.client.get('/browser/requests/'+rid)
        self.assertEqual(r.status_code,200,r.text)
        return dict(re.findall(r'name="([^"]+)" value="([^"]+)"',r.text))
    def test_rest_and_exact_browser_approval(self):
        r=self.request();form=self.form(r['request_id']);form['choice']='approve'
        result=self.client.post('/browser/requests/'+r['request_id']+'/decision',data=form,headers={'Origin':self.origin},follow_redirects=False)
        self.assertEqual(result.status_code,303,result.text)
        self.assertEqual(self.s.request(ACTOR,r['request_id']).state,'approved')
        self.assertNotEqual(self.client.post('/browser/requests/'+r['request_id']+'/decision',data=form,headers={'Origin':self.origin}).status_code,200)
    def test_bearer_cannot_use_human_route(self):
        r=self.request();form=self.form(r['request_id']);form['choice']='approve'
        self.assertEqual(self.client.post('/browser/requests/'+r['request_id']+'/decision',data=form,headers={**self.headers,'Origin':self.origin}).status_code,403)
    def test_csrf_origin_and_digest(self):
        r=self.request();form=self.form(r['request_id']);form['choice']='approve';form['csrf']='bad'
        self.assertEqual(self.client.post('/browser/requests/'+r['request_id']+'/decision',data=form,headers={'Origin':self.origin}).status_code,401)
        self.assertEqual(self.client.get('/v1/requests',headers={**self.headers,'Origin':'https://evil.invalid'}).status_code,403)
        form=self.form(r['request_id']);form['choice']='approve';form['digest']='0'*64
        self.assertEqual(self.client.post('/browser/requests/'+r['request_id']+'/decision',data=form,headers={'Origin':self.origin}).status_code,409)
    def test_no_executor_or_approval_rest_surface(self):
        self.assertEqual(self.client.post('/v1/execute',headers=self.headers,json={}).status_code,404)
        self.assertEqual(self.client.post('/v1/approve',headers=self.headers,json={}).status_code,404)
    def test_mcp_protocol_schema_and_pure_reads(self):
        r=self.request();headers={**self.headers,'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-06-18'}
        def rpc(method,params=None,id=1):
            return self.client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':id,'method':method,'params':params or {}})
        init=rpc('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'test','version':'1'}})
        self.assertEqual(init.status_code,200,init.text)
        tools=rpc('tools/list').json()['result']['tools']; self.assertGreater(len(tools),3)
        self.assertFalse(any('approve' in x['name'] or 'redeem' in x['name'] for x in tools))
        listing=next(x for x in tools if x['name']=='list_permission_requests');self.assertTrue(listing['annotations']['readOnlyHint']);self.assertIn('outputSchema',listing)
        with sqlite3.connect(self.s.path) as db: before='\n'.join(db.iterdump())
        reply=rpc('tools/call',{'name':'list_permission_requests','arguments':{}})
        self.assertEqual(reply.status_code,200,reply.text); self.assertIn('structuredContent',reply.json()['result'])
        with sqlite3.connect(self.s.path) as db: after='\n'.join(db.iterdump())
        self.assertEqual(before,after)
        self.assertNotIn('SecretAccessKey',reply.text)
    def test_mcp_notification_and_get(self):
        h={**self.headers,'Accept':'application/json, text/event-stream'}
        r=self.client.post('/mcp',headers=h,json={'jsonrpc':'2.0','method':'notifications/initialized'})
        self.assertEqual(r.status_code,202,r.text)
        self.assertEqual(self.client.get('/mcp',headers={**self.headers,'Accept':'text/event-stream'}).status_code,405)
    def test_missing_auth_and_oversized_body(self):
        self.assertEqual(self.client.get('/v1/status').status_code,401)
        self.assertEqual(self.client.post('/v1/requests',headers=self.headers,content='x'*17000).status_code,413)
