"""Explicit opt-in local fixture launcher. Never constructs live provider clients."""
import argparse
from .auth import BearerVerifier,BrowserAuth
from .http import create_app,HTTPConfig
from .service import Service

def main():
    p=argparse.ArgumentParser(); p.add_argument('--offline-fixture',action='store_true'); p.add_argument('--db',default='integration-offline.sqlite3'); p.add_argument('--port',type=int,default=8877)
    a=p.parse_args(); origin=f'http://127.0.0.1:{a.port}'
    if not a.offline_fixture: p.error('this launcher requires --offline-fixture; live runtime is unconfigured')
    from .fixtures import make_fixture
    import uvicorn
    service,bearer,browser=make_fixture(a.db,origin=origin)
    print('OFFLINE FIXTURE ONLY. Public token OFFLINE-ONLY. No live AWS or WorkOS calls.')
    uvicorn.run(create_app(service,bearer,browser,HTTPConfig(origin=origin,offline_mode=True)),host='127.0.0.1',port=a.port,access_log=False,log_level='warning')
if __name__=='__main__': main()
