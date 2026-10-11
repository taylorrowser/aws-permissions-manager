"""One offline-runnable service: website + REST + official MCP Streamable HTTP.
No executor/reconciliation/authority-install route is exposed.
"""
from contextlib import asynccontextmanager
from dataclasses import dataclass
from html import escape
from io import StringIO
from urllib.parse import parse_qs,urlparse
import json,time
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse,HTMLResponse,RedirectResponse,Response
from mcp.server.fastmcp import FastMCP,Context
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations,CallToolResult,TextContent,ClientRequest,ClientNotification
from .contracts import *
from .service import Denied,Unconfigured,Conflict
from .auth import AuthError,AuthUnconfigured

@dataclass(frozen=True)
class HTTPConfig:
    origin: str='https://unconfigured.invalid'
    offline_mode: bool=False
    authorization_server: str|None=None
    max_body_bytes: int=16384
    requests_per_minute: int=120


class SafeFastMCP(FastMCP):
    async def call_tool(self,name,arguments):
        try: return await super().call_tool(name,arguments)
        except Exception:
            return CallToolResult(isError=True,content=[TextContent(type='text',text='Tool request failed. Check its schema, authentication, grant, and current revision.')])


def create_app(service,bearer,browser,config=HTTPConfig(),*,coordinator=None):
    parsed=urlparse(config.origin)
    if parsed.path or parsed.query or parsed.fragment or parsed.username or not parsed.hostname:
        raise ValueError('an exact origin is required')
    if parsed.scheme!='https' and not (config.offline_mode and parsed.scheme=='http' and parsed.hostname in ('127.0.0.1','localhost','testserver')):
        raise ValueError('HTTPS required except explicit offline loopback')
    if config.offline_mode != service.offline_mode: raise ValueError('fixture mode mismatch')
    if not config.offline_mode and (getattr(bearer,'offline_only',False) or browser.offline_mode): raise ValueError('fixture authentication forbidden in production')
    if coordinator is not None:
        if coordinator.path!=service.path: raise ValueError('offline enrollment and grant commands require the same transactional store')
        service.run_guard=coordinator.get_run
    def principal(request): return bearer.verify_authorization(request.headers.get('authorization',''))
    def mp(ctx): return principal(ctx.request_context.request)
    mcp=SafeFastMCP('Permissions broker',instructions='Request exact existing-EC2 scope; a separate human browser approves. Credentials are delivered only by credential_process.',
        stateless_http=True,json_response=True,streamable_http_path='/mcp',log_level='CRITICAL',
        transport_security=TransportSecuritySettings(allowed_hosts=[parsed.netloc],allowed_origins=[config.origin]),max_request_body_size=config.max_body_bytes)
    read=ToolAnnotations(readOnlyHint=True,destructiveHint=False,idempotentHint=True,openWorldHint=False)
    write=ToolAnnotations(readOnlyHint=False,destructiveHint=False,idempotentHint=True,openWorldHint=False)

    @mcp.tool(annotations=read,structured_output=True)
    def list_permission_requests(ctx:Context)->RequestList:
        """List caller-owned requests. Pure query; never reconciles provider or journal state."""
        return service.requests(mp(ctx))
    @mcp.tool(annotations=read,structured_output=True)
    def get_permission_request(request_id:str,ctx:Context)->RequestView:
        """Read the latest exact request revision and operation status."""
        return service.request(mp(ctx),request_id)
    @mcp.tool(annotations=read,structured_output=True)
    def list_permission_grants(ctx:Context)->GrantList:
        """Read caller-owned grants, including derived expiration, without writes."""
        return service.grants(mp(ctx))
    @mcp.tool(annotations=write,structured_output=True)
    def request_permission_scope(request:RequestInput,ctx:Context)->RequestView:
        """Submit bounded EC2 scope with reason, expected generation and idempotency key for human review."""
        return service.submit(mp(ctx),request)
    @mcp.tool(annotations=write,structured_output=True)
    def revise_permission_request(request_id:str,revision:RevisionInput,ctx:Context)->RequestView:
        """Replace a pending revision. Prior digest/challenges cannot approve the new revision."""
        return service.submit(mp(ctx),revision.request,request_id,revision.expected_revision)
    @mcp.tool(annotations=read,structured_output=True)
    def get_permission_operation(operation_id:str,ctx:Context)->OperationView:
        """Read a durable operation ID; no execution or reconciliation occurs."""
        return service.operation(mp(ctx),operation_id)
    def require_coordinator():
        if coordinator is None: raise Unconfigured('trusted coordinator enrollment is not installed')
        return coordinator
    def prepare_enrollment_for(p,data):
        binding=service.enrollment_binding(p,data.grant_id)
        return EnrollmentPrepared(**require_coordinator().prepare(p,data.public_jwk,binding,data.lifetime,data.idempotency_key))
    @mcp.tool(annotations=write,structured_output=True)
    def prepare_run_enrollment(enrollment:EnrollmentPrepareInput,ctx:Context)->EnrollmentPrepared:
        """Authorize a task public key under existing standing coordinator trust. Mutates one-use enrollment state; public keys are NOT machine attestation. No AWS or login secrets are returned."""
        return prepare_enrollment_for(mp(ctx),enrollment)

    @mcp.tool(annotations=write,structured_output=True)
    def prepare_credential_use(lease:LeaseInput,ctx:Context)->CredentialLease:
        """Reserve a short-lived non-secret credential-use handle for an already trusted run. Use the CLI credential_process command; this tool never returns AWS credentials."""
        return service.lease(mp(ctx),lease)

    @asynccontextmanager
    async def lifespan(app):
        async with mcp.session_manager.run(): yield
    app=FastAPI(title='Permissions broker',version='0.1.0-offline',lifespan=lifespan,docs_url='/api-docs' if config.offline_mode else None,redoc_url=None)
    app.state.mcp=mcp; app.state.service=service
    rate={}
    @app.middleware('http')
    async def safeguards(request,call_next):
        host=request.headers.get('host','')
        if host!=parsed.netloc: return JSONResponse({'error':'host_not_allowed'},403)
        origin=request.headers.get('origin')
        if origin is not None and origin!=config.origin: return JSONResponse({'error':'origin_not_allowed'},403)
        if request.headers.get('content-length','0').isdigit() and int(request.headers.get('content-length','0'))>config.max_body_bytes:
            return JSONResponse({'error':'request_too_large'},413)
        # Bound all bodies including chunked input before any parser sees it.
        chunks=[]; size=0
        async for chunk in request.stream():
            size+=len(chunk)
            if size>config.max_body_bytes: return JSONResponse({'error':'request_too_large'},413)
            chunks.append(chunk)
        body=b''.join(chunks); request._body=body
        key=(request.client.host if request.client else 'unknown',int(time.time())//60)
        rate[key]=rate.get(key,0)+1
        for k in list(rate):
            if k[1]<key[1]-1: del rate[k]
        if rate[key]>config.requests_per_minute: return JSONResponse({'error':'rate_limited'},429,headers={'Retry-After':'60'})
        try:
            if request.url.path.startswith('/v1/') or request.url.path.rstrip('/')=='/mcp': principal(request)
            if request.url.path.rstrip('/')=='/mcp' and request.method=='POST':
                try: rpc=json.loads(body)
                except (ValueError,UnicodeError): return JSONResponse({'jsonrpc':'2.0','id':None,'error':{'code':-32700,'message':'Invalid JSON-RPC message'}},400)
                try:
                    if not isinstance(rpc,dict) or rpc.get('jsonrpc')!='2.0' or set(rpc)-{'jsonrpc','id','method','params'}: raise ValueError()
                    if 'id' in rpc and (type(rpc['id']) not in (str,int) or (isinstance(rpc['id'],str) and len(rpc['id'])>128)): raise ValueError()
                    (ClientRequest if 'id' in rpc else ClientNotification).model_validate(rpc)
                    if rpc.get('method') not in {'initialize','notifications/initialized','notifications/cancelled','notifications/progress','ping','tools/list','tools/call','resources/list','resources/templates/list','prompts/list'}: raise ValueError()
                except Exception:
                    return JSONResponse({'jsonrpc':'2.0','id':None,'error':{'code':-32600,'message':'Invalid or unsupported JSON-RPC request'}},400)
                if rpc.get('method')=='tools/call':
                    params=rpc.get('params')
                    known={t.name for t in await mcp.list_tools()}
                    if not isinstance(params,dict) or not isinstance(params.get('name'),str) or params.get('name') not in known:
                        rpc_id=rpc.get('id'); rpc_id=rpc_id if type(rpc_id) in (str,int) else None
                        return JSONResponse({'jsonrpc':'2.0','id':rpc_id,'result':{'isError':True,'content':[{'type':'text','text':'Unknown or invalid tool request'}]}})
            response=await call_next(request)
        except AuthUnconfigured: response=JSONResponse({'error':'authentication_unconfigured'},503)
        except AuthError: response=JSONResponse({'error':'authentication_required'},401,headers={'WWW-Authenticate':'Bearer resource_metadata="'+config.origin+'/.well-known/oauth-protected-resource/mcp"'})
        response.headers['Cache-Control']='no-store'; response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['Content-Security-Policy']="default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        return response
    @app.exception_handler(RequestValidationError)
    async def invalid_input(request,exc):
        return JSONResponse({'error':'invalid_request','fields':[list(e['loc']) for e in exc.errors()]},422)
    @app.exception_handler(Denied)
    async def denied(request,exc):
        return JSONResponse({'error':'unconfigured' if isinstance(exc,Unconfigured) else 'conflict' if isinstance(exc,Conflict) else 'forbidden','detail':str(exc)},503 if isinstance(exc,Unconfigured) else 409 if isinstance(exc,Conflict) else 403)
    @app.exception_handler(AuthError)
    async def auth_denied(request,exc):
        return JSONResponse({'error':'authentication_unconfigured' if isinstance(exc,AuthUnconfigured) else 'authentication_required'},503 if isinstance(exc,AuthUnconfigured) else 401)

    @app.get('/health')
    def health(): return {'mode':'OFFLINE FIXTURE' if config.offline_mode else 'UNCONFIGURED NON-LIVE','live_issuance':False}
    @app.get('/.well-known/oauth-protected-resource/mcp')
    def resource_metadata():
        if not config.authorization_server: raise Unconfigured('WorkOS authorization server is not configured')
        return {'resource':config.origin+'/mcp','authorization_servers':[config.authorization_server],'bearer_methods_supported':['header']}
    @app.get('/v1/status',response_model=SessionStatus)
    def status(request:Request):
        p=principal(request)
        return SessionStatus(authenticated=True,owner_id=p.owner_id,client_id=p.client_id,actor_kind=p.actor_kind,mode='offline' if config.offline_mode else 'unconfigured')
    @app.get('/v1/requests',response_model=RequestList)
    def requests(request:Request): return service.requests(principal(request))
    @app.post('/v1/requests',response_model=RequestView)
    def submit(data:RequestInput,request:Request): return service.submit(principal(request),data)
    @app.get('/v1/requests/{rid}',response_model=RequestView)
    def get_request(rid:str,request:Request): return service.request(principal(request),rid)
    @app.post('/v1/requests/{rid}/revisions',response_model=RequestView)
    def revise(rid:str,data:RevisionInput,request:Request): return service.submit(principal(request),data.request,rid,data.expected_revision)
    @app.get('/v1/grants',response_model=GrantList)
    def grants(request:Request): return service.grants(principal(request))
    @app.get('/v1/operations/{oid}',response_model=OperationView)
    def operation(oid:str,request:Request): return service.operation(principal(request),oid)
    @app.post('/v1/runs',response_model=RunIdentity)
    def enroll(data:RunEnrollmentInput,request:Request): return service.enroll(principal(request),data)
    @app.post('/v1/leases',response_model=CredentialLease)
    def lease(data:LeaseInput,request:Request): return service.lease(principal(request),data)
    @app.post('/v1/credential-process',include_in_schema=False)
    def credential_process(data:CredentialUseInput,request:Request):
        # Deliberately absent from MCP and OpenAPI examples. Disable access/body logging at hosting layer.
        envelope=service.redeem(principal(request),data.handle); stream=StringIO()
        envelope.write_credential_process(stream)
        return Response(stream.getvalue(),media_type='application/json',headers={'Cache-Control':'no-store'})

    @app.post('/v1/enrollments',response_model=EnrollmentPrepared)
    def prepare_enrollment(data:EnrollmentPrepareInput,request:Request): return prepare_enrollment_for(principal(request),data)
    @app.post('/enrollment/redeem')
    def redeem_enrollment(data:EnrollmentRedeemInput,request:Request):
        result=require_coordinator().redeem(data.enrollment_id,request.headers.get('dpop',''),method='POST',url=config.origin+'/enrollment/redeem',body_digest=digest(data.model_dump()))
        service.attach_trusted_run(result); return result
    @app.post('/run/{run_id}/nonce')
    def run_nonce(run_id:str): return {'nonce':require_coordinator().issue_nonce(run_id)}
    @app.post('/run/credential-process',include_in_schema=False)
    def run_credential(data:RunCredentialInput,request:Request):
        current=service.coordinator_current(data.grant_id)
        binding={k:current[k] for k in ('grant_id','revision','digest','roles','not_after')}
        summary=require_coordinator().validate_request(data.run_id,request.headers.get('dpop',''),method='POST',url=config.origin+'/run/credential-process',nonce=data.nonce,grant_binding=binding,body_digest=digest(data.model_dump()))
        from .auth import Principal
        p=Principal(summary['subject'],summary['owner_id'],summary['client_id'],'bearer_user',None,summary['authentication_id'])
        service.attach_trusted_run(summary)
        handle=service.lease(p,LeaseInput(grant_id=data.grant_id,run_id=data.run_id,idempotency_key=data.idempotency_key),key_bound=True)
        envelope=service.redeem(p,handle.handle,key_bound=True); stream=StringIO(); envelope.write_credential_process(stream)
        return Response(stream.getvalue(),media_type='application/json',headers={'DPoP-Nonce':summary['nonce'],'Cache-Control':'no-store'})

    def page(title,body):
        banner='<strong>OFFLINE FIXTURE: no live cloud permissions</strong>' if config.offline_mode else '<strong>Non-live integration: production setup required</strong>'
        return HTMLResponse('<!doctype html><html><head><meta charset="utf-8"><title>'+escape(title)+'</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:20px;background:#f7f8fc;color:#17233b}pre{white-space:pre-wrap;background:white;padding:20px;border:1px solid #d9dfeb}button{padding:10px 20px;margin:8px}strong{color:#8b3c00}a{color:#234ba2}</style></head><body>'+banner+'<h1>'+escape(title)+'</h1>'+body+'</body></html>')
    @app.get('/',response_class=HTMLResponse)
    def home():
        return page('Permissions broker','<p>Review exact existing-EC2 access changes before approval.</p><a href="/auth/login">Sign in with WorkOS</a>'+('<p><a href="/offline/login">Enter conspicuous offline owner fixture</a></p>' if config.offline_mode else ''))
    @app.get('/auth/login')
    def login():
        start=browser.start_login(); response=RedirectResponse(start.authorization_url,303)
        opts=dict(browser.cookie_options); opts['samesite']='lax'
        response.set_cookie(browser.state_cookie_name,start.state_cookie,**opts); return response
    @app.get('/auth/callback')
    def callback(request:Request,code:str,state:str):
        result=browser.finish_login(code=code,state=state,state_cookie=request.cookies.get(browser.state_cookie_name,''))
        response=RedirectResponse('/browser/requests',303); response.set_cookie(browser.cookie_name,result.session_cookie,**browser.cookie_options)
        response.delete_cookie(browser.state_cookie_name,path='/'); return response
    if config.offline_mode:
        @app.get('/offline/login')
        def offline_login():
            from .auth import Principal
            p=Principal(subject='fixture-owner',owner_id=service.owner_id,client_id=service.browser_client_id,actor_kind='bearer_user',organization_id=None,authentication_id='fixture-browser-login')
            result=browser.fixture_login(p); response=RedirectResponse('/browser/requests',303)
            response.set_cookie(browser.cookie_name,result.session_cookie,**browser.cookie_options); return response
    def session(request):
        # A bearer credential, even for the owner, is NEVER accepted here.
        if request.headers.get('authorization'): raise Denied('browser-only approval route rejects bearer credentials')
        return browser.human_session(request.cookies.get(browser.cookie_name,''))
    @app.get('/browser/grants')
    def human_grants(request:Request):
        s=session(request); chunks=[]
        for grant in service.grants(s.principal).grants:
            current=service.coordinator_current(grant.grant_id); binding_digest=current['digest']
            challenge=browser.new_challenge(s,grant.grant_id,grant.generation,binding_digest)
            fields={'revision':str(grant.generation),'digest':binding_digest,'challenge':challenge,'csrf':s.csrf}
            form='<form method="post" action="/browser/grants/'+escape(grant.grant_id)+'/stop">'+''.join('<input type="hidden" name="'+k+'" value="'+escape(v,quote=True)+'">' for k,v in fields.items())+'<button>Stop new issuance</button></form>'
            chunks.append('<h2>'+escape(grant.logical_role)+'</h2><pre>'+escape(grant.model_dump_json(indent=2))+'</pre>'+form)
        return page('Active grants and issuance controls','<p>Stopping issuance does not instantly revoke credentials already issued by AWS.</p>'+''.join(chunks))
    @app.post('/browser/grants/{gid}/stop')
    async def stop_grant(gid:str,request:Request):
        s=session(request)
        try: values=parse_qs((await request.body()).decode('utf-8'),strict_parsing=True)
        except (UnicodeError,ValueError): raise Denied('invalid stop form')
        if set(values)!={'revision','digest','challenge','csrf'} or any(len(v)!=1 for v in values.values()): raise Denied('invalid stop form')
        form={k:v[0] for k,v in values.items()}
        grants={g.grant_id:g for g in service.grants(s.principal).grants}; grant=grants.get(gid)
        if not grant: raise Denied('resource unavailable')
        current=service.coordinator_current(gid)
        if form['revision']!=str(grant.generation) or form['digest']!=current['digest']: raise Conflict('grant changed')
        p=browser.consume_challenge(s,request.headers.get('origin',''),form['csrf'],form['challenge'],gid,grant.generation,current['digest'])
        service.stop_grant(p,gid); return RedirectResponse('/browser/grants',303)
    @app.post('/auth/logout')
    async def browser_logout(request:Request):
        import hmac
        s=session(request)
        if request.headers.get('origin')!=config.origin or not hmac.compare_digest(request.headers.get('x-csrf-token',''),s.csrf): raise Denied('invalid logout proof')
        browser.logout(request.cookies.get(browser.cookie_name));response=RedirectResponse('/',303);response.delete_cookie(browser.cookie_name,path='/');return response
    @app.get('/browser/requests')
    def human_requests(request:Request):
        s=session(request); rows=service.requests(s.principal).requests
        return page('Requests awaiting your review','<p><a href="/browser/grants">Manage grants</a></p>'+''.join('<p><a href="/browser/requests/'+escape(r.request_id)+'">'+escape(r.manifest['logical_role'])+'</a> · '+escape(r.state)+'</p>' for r in rows))
    @app.get('/browser/requests/{rid}')
    def review(rid:str,request:Request):
        s=session(request); view=service.request(s.principal,rid)
        challenge=browser.new_challenge(s,rid,view.revision,view.digest)
        hidden={'revision':str(view.revision),'digest':view.digest,'challenge':challenge,'csrf':s.csrf}
        form='<form method="post" action="/browser/requests/'+escape(rid)+'/decision">'+''.join('<input type="hidden" name="'+k+'" value="'+escape(v,quote=True)+'">' for k,v in hidden.items())+'<button name="choice" value="approve">Approve this exact revision</button><button name="choice" value="reject">Reject</button><button name="choice" value="cancel">Cancel before provider execution</button></form>'
        return page('Review exact permission change','<p>'+escape(view.manifest['reason'])+'</p><p>Digest: '+view.digest+'</p><p>New physical role ARN; prior issuance stops at approval. Existing AWS leases must drain before the change takes effect. Temporary changes must meet their exact approved start.</p><pre>'+escape(json.dumps(view.manifest,indent=2))+'</pre>'+form)
    @app.post('/browser/requests/{rid}/decision')
    async def decision(rid:str,request:Request):
        s=session(request)
        if request.headers.get('content-type','').split(';')[0]!='application/x-www-form-urlencoded': raise Denied('browser form required')
        try: parsed_form=parse_qs((await request.body()).decode('utf-8'),strict_parsing=True)
        except (UnicodeError,ValueError): raise Denied('invalid browser decision form')
        if set(parsed_form)!={'revision','digest','challenge','csrf','choice'} or any(len(v)!=1 for v in parsed_form.values()): raise Denied('invalid browser decision form')
        form={k:v[0] for k,v in parsed_form.items()}
        try: revision=int(form['revision'])
        except ValueError: raise Denied('invalid revision')
        current=service.request(s.principal,rid)
        if current.revision!=revision or current.digest!=form['digest']: raise Conflict('request changed; review the latest revision')
        p=browser.consume_challenge(s,request.headers.get('origin',''),form['csrf'],form['challenge'],rid,revision,form['digest'])
        if form['choice']=='cancel': service.cancel_pending(p,rid,revision,form['digest'])
        else: service.decide(p,rid,revision,form['digest'],form['choice'])
        return RedirectResponse('/browser/requests/'+rid,303)
    @app.get('/mcp',include_in_schema=False)
    def no_sse(): return Response(status_code=405,headers={'Allow':'POST'})
    @app.delete('/mcp',include_in_schema=False)
    def no_sessions(): return Response(status_code=405,headers={'Allow':'POST'})
    app.mount('/',mcp.streamable_http_app())
    return app
