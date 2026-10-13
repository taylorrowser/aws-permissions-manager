"""Permission broker CLI; browser/device login boundary, no pasted-key interface."""
from dataclasses import asdict
from pathlib import Path
import argparse,json,os,stat,sys,time,tempfile,webbrowser
from urllib.parse import urlparse
import httpx
from .auth import DeviceTokens,UnconfiguredDeviceAuth,AuthError,AuthUnconfigured

class CLIError(Exception): pass

class TokenStore:
    """Explicit local token persistence. Prefer OS keychain in a future live adapter.
    Symlink and lax-mode files/directories are rejected; tokens never enter argv.
    """
    def __init__(self,path): self.path=Path(path)
    def _directory(self):
        parent=self.path.parent
        if parent.exists():
            if parent.is_symlink() or not parent.is_dir() or stat.S_IMODE(parent.stat().st_mode)&0o077:
                raise CLIError('token directory must be private (0700), not a symlink')
        else: parent.mkdir(mode=0o700,parents=True)
    def save(self,tokens):
        self._directory()
        if self.path.exists() or self.path.is_symlink():
            if self.path.is_symlink() or not self.path.is_file(): raise CLIError('unsafe token path')
        fd,name=tempfile.mkstemp(prefix='.tokens-',dir=self.path.parent)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'w') as f:
                json.dump(asdict(tokens),f); f.flush(); os.fsync(f.fileno())
            os.replace(name,self.path)
        finally:
            if os.path.exists(name): os.unlink(name)
    def load(self):
        self._directory()
        try:
            fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd) as f:
                st=os.fstat(f.fileno())
                if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode)&0o077 or st.st_uid!=os.getuid(): raise CLIError('unsafe token file permissions')
                data=json.load(f)
            return DeviceTokens(**data)
        except (OSError,ValueError,TypeError): raise CLIError('log in first; token storage unavailable') from None
    def clear(self):
        if self.path.is_symlink(): raise CLIError('unsafe token path')
        try: self.path.unlink()
        except FileNotFoundError: pass

class Client:
    def __init__(self,origin,store,provider=None,*,offline=False,transport=None):
        p=urlparse(origin)
        if p.username or p.password or p.path or p.query or p.fragment or not p.hostname or (p.scheme!='https' and not (offline and p.scheme=='http' and p.hostname in ('127.0.0.1','localhost'))): raise CLIError('exact HTTPS broker origin required')
        self.origin=origin; self.store=store; self.provider=provider or UnconfiguredDeviceAuth(); self.offline=offline
        self._transport=transport; self._http=None
    @property
    def http(self):
        if self._http is None:
            self._http=httpx.Client(base_url=self.origin,follow_redirects=False,timeout=15,transport=self._transport)
        return self._http
    def login(self,display=lambda x:None,clock=time.monotonic,sleep=time.sleep):
        if self.offline:
            self.store.save(DeviceTokens('OFFLINE-ONLY','OFFLINE-ONLY',3600)); return {'authenticated':True,'mode':'OFFLINE FIXTURE'}
        challenge=self.provider.start()
        if not challenge.verification_uri.startswith('https://') or not 1<=challenge.interval<=60 or not 1<=challenge.expires_in<=1800: raise CLIError('invalid device authorization response')
        display({'verification_uri':challenge.verification_uri,'user_code':challenge.user_code})
        deadline=clock()+challenge.expires_in
        while clock()<deadline:
            sleep(challenge.interval); tokens=self.provider.poll(challenge.device_code)
            if tokens:
                self.store.save(tokens); return {'authenticated':True}
        raise CLIError('device authorization expired; login again')
    def logout(self):
        try:
            tokens=self.store.load()
            if not self.offline: self.provider.revoke(tokens.refresh_token)
        finally: self.store.clear()
        return {'logged_out':True}
    def call(self,method,path,data=None,refresh=True):
        tokens=self.store.load()
        try: response=self.http.request(method,path,json=data,headers={'Authorization':'Bearer '+tokens.access_token,'Accept':'application/json'})
        except httpx.HTTPError: raise CLIError('broker unavailable; no response body logged') from None
        if response.status_code==401 and refresh and not self.offline:
            try: self.store.save(self.provider.refresh(tokens.refresh_token))
            except Exception: raise CLIError('authentication expired; login again') from None
            return self.call(method,path,data,refresh=False)
        if response.status_code==401: raise CLIError('authentication expired; login again')
        if response.status_code==403: raise CLIError('access denied; an app-owned grant or browser approval is required')
        if response.status_code==409: raise CLIError('stale or conflicting request; fetch latest status and revise')
        if response.status_code==429: raise CLIError('rate limited; retry after '+str(response.headers.get('Retry-After','60'))[:10]+' seconds')
        if response.status_code>=500: raise CLIError('broker or provider is unavailable/unconfigured; retry later')
        if response.status_code>=300: raise CLIError('unexpected broker response; redirects are not followed')
        try: return response.json()
        except ValueError: raise CLIError('invalid broker response') from None

def main(argv=None,*,provider=None,transport=None,stdout=None,stderr=None):
    out=stdout or sys.stdout; err=stderr or sys.stderr
    p=argparse.ArgumentParser(prog='permission-broker'); p.add_argument('--origin',default='https://unconfigured.invalid'); p.add_argument('--json',action='store_true'); p.add_argument('--offline-fixture',action='store_true'); p.add_argument('--token-store',default=str(Path.home()/'.config/permission-broker/tokens.json'))
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('login','logout','status','requests','grants'): sub.add_parser(name)
    for name in ('request','enroll','lease'): sub.add_parser(name).add_argument('--file',required=True)
    sub.add_parser('request-status').add_argument('request_id'); sub.add_parser('operation').add_argument('operation_id')
    s=sub.add_parser('revise');s.add_argument('request_id');s.add_argument('--file',required=True)
    sub.add_parser('credential-process').add_argument('--handle',required=True)
    a=p.parse_args(argv)
    try:
        c=Client(a.origin,TokenStore(a.token_store),provider,offline=a.offline_fixture,transport=transport)
        if a.command=='login':
            # User code is one-time login UX, not an AWS key. Never display tokens.
            result=c.login(display=lambda value: print(json.dumps(value),file=err))
        elif a.command=='logout': result=c.logout()
        elif a.command=='credential-process':
            if out.isatty(): raise CLIError('credential-process refuses terminal output; configure it as an AWS subprocess')
            result=c.call('POST','/v1/credential-process',{'handle':a.handle})
            if set(result)!={'Version','AccessKeyId','SecretAccessKey','SessionToken','Expiration'} or result.get('Version')!=1: raise CLIError('invalid credential-process response')
            print(json.dumps(result,separators=(',',':')),file=out); return 0
        else:
            method='GET'; data=None
            if a.command in ('request','enroll','lease','revise'):
                method='POST'
                with open(a.file) as f: data=json.load(f)
                path={'request':'/v1/requests','enroll':'/v1/runs','lease':'/v1/leases','revise':'/v1/requests/'+getattr(a,'request_id','')+'/revisions'}[a.command]
            else: path={'status':'/v1/status','requests':'/v1/requests','grants':'/v1/grants','request-status':'/v1/requests/'+getattr(a,'request_id',''),'operation':'/v1/operations/'+getattr(a,'operation_id','')}[a.command]
            result=c.call(method,path,data)
        print(json.dumps(result,indent=None if a.json else 2),file=out); return 0
    except (CLIError,AuthError,OSError,ValueError):
        # Do not print arbitrary provider exceptions or response data.
        print(json.dumps({'error':'command_failed','guidance':'Check configuration, login, grant status, or the offline instructions. No credential body was logged.'}),file=err); return 1
if __name__=='__main__': raise SystemExit(main())
