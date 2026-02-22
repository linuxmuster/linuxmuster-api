#! /usr/bin/env python3

import time
import uvicorn
import yaml
import os
import sys
import base64
import binascii
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi
from vars import *

config = {}
config_path = '/etc/linuxmuster/api/config.yml'
if os.path.isfile(config_path):
    os.chmod(config_path, 384)
    with open(config_path, 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.SafeLoader)

app = FastAPI(
    title = TITLE,
    version=VERSION,
    description = DESCRIPTION,
    swagger_ui_parameters = {"tryItOutEnabled": True, "swagger_favicon_url": "/static/favicon.png"},
    license_info={
        "name": "GNU General Public License v3.0 only",
        "url": "https://www.gnu.org/licenses/gpl-3.0.html"
    },
)

app.mount("/static", StaticFiles(directory="static"), name="static")

if config.get("cors", {}):
    app.add_middleware(
        CORSMiddleware,
        allow_origins     = config["cors"].get("allow_origins", []),
        allow_credentials = config["cors"].get("allow_credentials", True),
        allow_methods     = config["cors"].get("allow_methods", ["*"]),
        allow_headers     = config["cors"].get("allow_headers", ["*"]),
    )

# V1
from routers_v1 import (
    admins,
    auth,
    devices,
    exam,
    extraclasses,
    groups,
    listmanagement,
    query,
    managementgroups,
    print_passwords,
    printers,
    projects,
    roles,
    samba,
    schoolclasses,
    schools,
    server,
    sessions,
    teachers,
    users,
)

@app.middleware("http")
async def add_process_time_logging(request: Request, call_next):
    """
    Middleware to check process time of a request.
    """

    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

@app.get("/", response_class=HTMLResponse, tags=["Home"])
def home():
    """
    ### Default root response
    """

    return HTML_HOME

app.include_router(auth.router, prefix="/v1")
app.include_router(admins.router_global, prefix="/v1")
app.include_router(devices.router, prefix="/v1")
app.include_router(exam.router, prefix="/v1")
app.include_router(extraclasses.router, prefix="/v1")
app.include_router(groups.router, prefix="/v1")
app.include_router(listmanagement.router, prefix="/v1")
app.include_router(managementgroups.router, prefix="/v1")
app.include_router(print_passwords.router, prefix="/v1")
app.include_router(printers.router, prefix="/v1")
app.include_router(projects.router, prefix="/v1")
app.include_router(query.router, prefix="/v1")
app.include_router(roles.router, prefix="/v1")
app.include_router(samba.router, prefix="/v1")
app.include_router(schoolclasses.router, prefix="/v1")
app.include_router(server.router, prefix="/v1")
app.include_router(sessions.router, prefix="/v1")
app.include_router(schools.router, prefix="/v1")
app.include_router(teachers.router, prefix="/v1")
app.include_router(users.router, prefix="/v1")

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title = TITLE,
        version = VERSION,
        summary = TITLE,
        description = DESCRIPTION,
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        'HTTPBasic': {'type': 'http', 'scheme': 'basic'},
        'ApiKeyUserAuth': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'},
        'ApiKeyHostAuth': {'type': 'apiKey', 'in': 'header', 'name': 'X-HOST-Key'},
    }
    for path, details in openapi_schema["paths"].items():
        if path != '/v1/auth/' and path != '/':
            for method in details.keys():
                details[method]['security'] = [{'ApiKeyUserAuth': [], 'ApiKeyHostAuth': []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

def list_all_endpoints(filter_str=''):
    max_name = 50
    max_path = 50
    max_reg = 50

    def _roles(depend):
        raw_roles = getattr(depend, 'roles', '')
        if not raw_roles:
            return ''
        roles = []
        for role in raw_roles:
            roles.append(role.replace('administrator', 'adm'))
        return ';'.join(roles)

    for data in app.routes:
        if len(data.path) > max_path:
            max_path = len(data.path)
        if len(data.name) > max_name:
            max_name = len(data.name)
        if len(data.path_regex.pattern) > max_reg:
            max_reg = len(data.path_regex.pattern)

    print("-"*(max_reg+max_path+max_name+60))
    print(f"{"URL":{max_path}} | {"Desc.":{max_name}} | {"Regexp":{max_reg}} | {'Roles'}")
    print("-"*(max_reg+max_path+max_name+60))
    for data in app.routes:
        if hasattr(data, 'dependant'):
            if data.dependant.dependencies:
                line = f"{data.path:{max_path}} | {data.name:{max_name}} | {data.path_regex.pattern:{max_reg}} | {_roles(data.dependant.dependencies[0].call)}"
        else:
            line = f"{data.path:{max_path}} | {data.name:{max_name}} | {' '*max_reg} |"

        if filter_str in line:
            print(line)

    print("-"*(max_reg+max_path+max_name+60))

app.openapi = custom_openapi

if __name__ == "__main__":
    secret = config.get('secret', None)
    if not secret:
        print('Linuxmuster-api can not work without secret key, please configure it first.')
        sys.exit(1)

    try:
        secret_decoded = base64.b64decode(secret)
        if len(secret_decoded) < 64:
            print('Secret key should at least be 512 bits long for an optimal security.')
            sys.exit(1)
    except binascii.Error as e:
        print(f'Invalid secret key in config.yml: {e}')
        sys.exit(1)

    secret = ''

    # Ensure config data
    config.setdefault('uvicorn', {})
    config['uvicorn'].setdefault('host', '0.0.0.0')
    config['uvicorn'].setdefault('port', 8001)

    # Using the same certificates as the Webui
    config['uvicorn'].setdefault('ssl_keyfile', '/etc/linuxmuster/api/lmnapi.pem')
    config['uvicorn'].setdefault('ssl_certfile', '/etc/linuxmuster/api/lmnapi.pem')
    config['uvicorn'].setdefault('log_level', 'info')
    config['uvicorn'].setdefault('log_config', '/etc/linuxmuster/api/uvicorn_log_conf.yml')

    uvicorn.run("main:app", **config['uvicorn'])
