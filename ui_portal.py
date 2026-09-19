"""Same-origin application screen and fixed JANUS sign-in delegation."""
import json
from urllib import request, error
from urllib.parse import urlsplit
from fastapi import Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

class MfaCode(BaseModel):
    code: str = Field(min_length=6,max_length=8)

class Login(BaseModel):
    email: str = Field(min_length=3,max_length=254)
    password: str = Field(min_length=1,max_length=512)

class RecoveryIssue(BaseModel):
    email: str = Field(min_length=3,max_length=254)

class RecoveryRedeem(BaseModel):
    email: str = Field(min_length=3,max_length=254)
    code: str = Field(min_length=3,max_length=128)
    new_password: str = Field(min_length=12,max_length=512)

class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

def open_request(req):
    return request.build_opener(NoRedirect()).open(req,timeout=8)

def install_ui(app,page,janus_url=None):
    def screen():
        return FileResponse(page,media_type='text/html',headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"})
    app.add_api_route('/',screen,methods=['GET'],include_in_schema=False)
    app.add_api_route('/ui',screen,methods=['GET'],include_in_schema=False)
    if not janus_url:return
    parsed=urlsplit(janus_url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError('UI sign-in requires a fixed HTTPS JANUS authority')
    base=janus_url.rstrip('/')

    def janus_json_proxy(path, authorization, body=None, method='POST'):
        if not authorization.lower().startswith('bearer '):
            raise HTTPException(401,'Session required')
        data = None if body is None else json.dumps(body).encode()
        headers = {'Authorization':authorization,'Accept':'application/json'}
        if data is not None:
            headers['Content-Type']='application/json'
        req=request.Request(base+path,data=data,headers=headers,method=method)
        try:
            with open_request(req) as response:
                raw=response.read(65536)
                payload=json.loads(raw or b'{}')
            return JSONResponse(payload,headers={'Cache-Control':'no-store'})
        except error.HTTPError as exc:
            if exc.code in (400,401,403,409,423,429):
                detail='JANUS high-assurance request denied'
                try:
                    body=json.loads(exc.read(65536))
                    if isinstance(body,dict) and isinstance(body.get('detail'),str):
                        detail=body['detail']
                except Exception:
                    pass
                raise HTTPException(exc.code,detail) from None
            raise HTTPException(503,'JANUS high-assurance service is unavailable') from None
        except (OSError,error.URLError,ValueError):
            raise HTTPException(503,'JANUS high-assurance service is unavailable') from None

    @app.post('/ui/session')
    def login(body:Login):
        req=request.Request(base+'/v1/auth/login',data=json.dumps(body.model_dump()).encode(),headers={'Content-Type':'application/json'},method='POST')
        try:
            with open_request(req) as response:payload=json.loads(response.read(65536))
            if not isinstance(payload,dict) or not isinstance(payload.get('access_token'),str) or not payload['access_token']:
                raise ValueError('Invalid identity response')
        except error.HTTPError as exc:
            if exc.code in (400,401,403,423,429):
                raise HTTPException(exc.code,'JANUS sign-in denied. Check your identity credentials.') from None
            raise HTTPException(503,'JANUS sign-in is unavailable') from None
        except (OSError,error.URLError,ValueError):
            raise HTTPException(503,'JANUS sign-in is unavailable') from None
        return JSONResponse(payload,headers={'Cache-Control':'no-store'})

    @app.post('/ui/recovery/issue')
    def recovery_issue(body:RecoveryIssue):
        req=request.Request(base+'/v1/auth/recovery/issue',data=json.dumps(body.model_dump()).encode(),headers={'Content-Type':'application/json','Accept':'application/json'},method='POST')
        try:
            with open_request(req) as response:payload=json.loads(response.read(65536))
            return JSONResponse(payload,headers={'Cache-Control':'no-store'})
        except error.HTTPError as exc:
            detail='JANUS recovery request denied'
            try:
                body=json.loads(exc.read(65536))
                if isinstance(body,dict) and isinstance(body.get('detail'),str):detail=body['detail']
            except Exception:pass
            raise HTTPException(exc.code if exc.code in (400,401,403,404,409,423,429) else 503,detail) from None
        except (OSError,error.URLError,ValueError):
            raise HTTPException(503,'JANUS recovery service is unavailable') from None

    @app.post('/ui/recovery/redeem')
    def recovery_redeem(body:RecoveryRedeem):
        req=request.Request(base+'/v1/auth/recovery/redeem',data=json.dumps(body.model_dump()).encode(),headers={'Content-Type':'application/json','Accept':'application/json'},method='POST')
        try:
            with open_request(req) as response:payload=json.loads(response.read(65536))
            return JSONResponse(payload,headers={'Cache-Control':'no-store'})
        except error.HTTPError as exc:
            detail='JANUS recovery reset denied'
            try:
                body=json.loads(exc.read(65536))
                if isinstance(body,dict) and isinstance(body.get('detail'),str):detail=body['detail']
            except Exception:pass
            raise HTTPException(exc.code if exc.code in (400,401,403,404,409,423,429) else 503,detail) from None
        except (OSError,error.URLError,ValueError):
            raise HTTPException(503,'JANUS recovery service is unavailable') from None

    @app.post('/ui/mfa/enroll')
    def mfa_enroll(authorization:str=Header(default='')):
        return janus_json_proxy('/v1/auth/mfa/enroll',authorization,{})

    @app.post('/ui/mfa/confirm')
    def mfa_confirm(body:MfaCode,authorization:str=Header(default='')):
        return janus_json_proxy('/v1/auth/mfa/confirm',authorization,body.model_dump())

    @app.post('/ui/mfa/step-up')
    def mfa_step_up(body:MfaCode,authorization:str=Header(default='')):
        return janus_json_proxy('/v1/auth/step-up',authorization,body.model_dump())

    @app.delete('/ui/session')
    def logout(authorization:str=Header(default='')):
        if not authorization.lower().startswith('bearer '):raise HTTPException(401,'Session required')
        req=request.Request(base+'/v1/auth/logout',data=b'',headers={'Authorization':authorization},method='POST')
        try:
            with open_request(req) as response:response.read(4096)
        except (OSError,error.URLError):
            raise HTTPException(503,'JANUS session revocation is unavailable') from None
        return {'logged_out':True}
