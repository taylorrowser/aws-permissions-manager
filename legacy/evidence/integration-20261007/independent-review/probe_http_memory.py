import tempfile, asyncio, json
from integration.fixtures import make_fixture
from integration.http import create_app,HTTPConfig
origin='http://127.0.0.1:8877'
async def probe(app):
 consumed=0;out=[]
 async def receive():
  nonlocal consumed
  if consumed<100:
   consumed+=1
   return {'type':'http.request','body':b'x'*1024,'more_body':consumed<100}
  return {'type':'http.disconnect'}
 async def send(event):out.append(event)
 scope={'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':'POST','scheme':'http','path':'/v1/requests','raw_path':b'/v1/requests','query_string':b'','headers':[(b'host',b'127.0.0.1:8877'),(b'authorization',b'Bearer OFFLINE-ONLY'),(b'content-type',b'application/json')],'client':('127.0.0.1',1234),'server':('127.0.0.1',8877)}
 await app(scope,receive,send)
 return {'configured_max_body_bytes':4096,'received_bytes_before_rejection':consumed*1024,'status':next(x['status'] for x in out if x['type']=='http.response.start')}
with tempfile.TemporaryDirectory() as t:
 s,b,ba=make_fixture(t+'/db',origin=origin)
 print(json.dumps(asyncio.run(probe(create_app(s,b,ba,HTTPConfig(origin=origin,offline_mode=True,max_body_bytes=4096)))),indent=2))
