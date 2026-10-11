import unittest,tempfile,os,json,io
import httpx
from integration.cli import *
from integration.auth import DeviceTokens
class CLITests(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory();self.path=self.tmp.name+'/private/tokens.json';self.store=TokenStore(self.path)
    def tearDown(self): self.tmp.cleanup()
    def test_store_private_and_logout(self):
        self.store.save(DeviceTokens('test-access','test-refresh',100));self.assertEqual(os.stat(self.path).st_mode&0o777,0o600)
        self.assertNotIn('test-access',repr(self.store.load()));self.store.clear();self.assertFalse(os.path.exists(self.path))
    def test_symlink_and_lax_directory_denied(self):
        os.mkdir(self.tmp.name+'/private',0o755)
        with self.assertRaises(CLIError): self.store.save(DeviceTokens('a','b',1))
        os.chmod(self.tmp.name+'/private',0o700);os.symlink(self.tmp.name+'/target',self.path)
        with self.assertRaises(CLIError): self.store.save(DeviceTokens('a','b',1))
    def test_login_default_unconfigured(self):
        c=Client('https://broker.invalid',self.store)
        with self.assertRaises(AuthUnconfigured): c.login()
    def test_offline_login_status_json(self):
        def transport(request): return httpx.Response(200,json={'authenticated':True,'mode':'offline'})
        args=['--origin','http://127.0.0.1:8877','--offline-fixture','--token-store',self.path,'--json']
        out=io.StringIO();self.assertEqual(main(args+['login'],stdout=out),0)
        out=io.StringIO();self.assertEqual(main(args+['status'],transport=httpx.MockTransport(transport),stdout=out),0)
        self.assertEqual(json.loads(out.getvalue())['authenticated'],True)
    def test_https_redirect_and_secret_error_hygiene(self):
        with self.assertRaises(CLIError): Client('http://evil.invalid',self.store,offline=True)
        self.store.save(DeviceTokens('test-access','test-refresh',100))
        c=Client('https://broker.invalid',self.store,transport=httpx.MockTransport(lambda r:httpx.Response(500,json={'secret':'MUST_NOT_LEAK'})))
        with self.assertRaises(CLIError) as cm:c.call('GET','/v1/status')
        self.assertNotIn('MUST_NOT_LEAK',str(cm.exception))
    def test_credential_process_refuses_tty(self):
        class TTY(io.StringIO):
            def isatty(self):return True
        err=io.StringIO();out=TTY()
        result=main(['--token-store',self.path,'credential-process','--handle','x'],stdout=out,stderr=err)
        self.assertEqual(result,1);self.assertEqual(out.getvalue(),'')
    def test_credential_process_private_stdout(self):
        self.store.save(DeviceTokens('access','refresh',100));out=io.StringIO();err=io.StringIO()
        body={'Version':1,'AccessKeyId':'FAKE','SecretAccessKey':'FAKE_SECRET','SessionToken':'FAKE_TOKEN','Expiration':'2030-01-01T00:00:00Z'}
        result=main(['--origin','https://broker.invalid','--token-store',self.path,'credential-process','--handle','public-handle'],transport=httpx.MockTransport(lambda r:httpx.Response(200,json=body)),stdout=out,stderr=err)
        self.assertEqual(result,0);self.assertEqual(json.loads(out.getvalue()),body);self.assertEqual(err.getvalue(),'')
    def test_consumer_receives_credentials_but_reports_only_harmless_result(self):
        # Model an AWS SDK/CLI consumer's private subprocess pipe, not agent-visible exec capture.
        self.store.save(DeviceTokens('access','refresh',100))
        private_pipe=io.StringIO(); logs=io.StringIO()
        secret_body={'Version':1,'AccessKeyId':'FAKE_KEY','SecretAccessKey':'DO_NOT_REPORT_SECRET','SessionToken':'DO_NOT_REPORT_TOKEN','Expiration':'2030-01-01T00:00:00Z'}
        code=main(['--origin','https://broker.invalid','--token-store',self.path,'credential-process','--handle','handle'],transport=httpx.MockTransport(lambda r:httpx.Response(200,json=secret_body)),stdout=private_pipe,stderr=logs)
        self.assertEqual(code,0)
        credentials=json.loads(private_pipe.getvalue())
        # A consumer would now configure its SDK internally. Only a harmless result is surfaced.
        harmless={'operation':'DescribeInstances','instance_count':1,'authenticated':bool(credentials['AccessKeyId'])}
        reported=json.dumps(harmless)+logs.getvalue()
        self.assertNotIn('DO_NOT_REPORT',reported);self.assertNotIn('SecretAccessKey',reported)
