#! /usr/bin/env python3

import time
import uvicorn
import yaml
import os
import sys
import base64
import binascii
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi
from vars import *


from utils.checks import check_tmp_dir

config = {}
config_path = '/etc/linuxmuster/api/config.yml'
if os.path.isfile(config_path):
    os.chmod(config_path, 384)
    with open(config_path, 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.SafeLoader)

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.secret = base64.b64decode(config['secret']) if config.get('secret') else None
    app.state.host_keys = config.get('host_keys', {})
    app.state.host_key_auth_enable = config.get('host_key_auth', False)
    app.state.notifications = config.get('notifications', {})
    yield

app = FastAPI(
    title = TITLE,
    version=VERSION,
    description = DESCRIPTION,
    lifespan=lifespan,
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
    bindusers,
    auth,
    devices,
    exam,
    extraclasses,
    groups,
    linbo,
    linbo_drivers,
    linbo_sync,
    listmanagement,
    query,
    managementgroups,
    passwordconstraints,
    print_passwords,
    printers,
    projects,
    roles,
    samba,
    schoolclasses,
    schools,
    server,
    sessions,
    subnets,
    teachers,
    users,
    vdi,
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

_V1_PREFIX = "/v1"
_V1_ROUTERS = [
    auth.router,
    admins.router_global,
    admins.router_school,
    bindusers.router_global,
    bindusers.router_school,
    devices.router,
    exam.router,
    extraclasses.router,
    groups.router,
    linbo.router,
    linbo_drivers.router,
    linbo_sync.router,
    listmanagement.router,
    managementgroups.router,
    passwordconstraints.router,
    print_passwords.router,
    printers.router,
    projects.router,
    query.router,
    roles.router,
    samba.router,
    schoolclasses.router,
    server.router,
    sessions.router,
    subnets.router,
    schools.router,
    teachers.router,
    users.router,
    vdi.router,
]

for _router in _V1_ROUTERS:
    app.include_router(_router, prefix=_V1_PREFIX)

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

def _iter_effective_routes():
    # Since FastAPI 0.137, app.include_router() no longer flattens sub-router
    # routes into app.routes: each inclusion is kept as a lazy wrapper with no
    # .path/.path_regex of its own (only a real route has .path_regex, hence
    # the duck-typing check below instead of importing FastAPI's private
    # wrapper type). So top-level routes (home, static, docs, openapi) are
    # read straight off app.routes, while v1 endpoints are read directly off
    # the original router objects, with the "/v1" prefix applied manually.
    for route in app.routes:
        if hasattr(route, 'path_regex'):
            yield route, route.path, route.path_regex.pattern

    for router in _V1_ROUTERS:
        for route in router.routes:
            pattern = route.path_regex.pattern
            if pattern.startswith('^'):
                display_regex = f"^{_V1_PREFIX}{pattern[1:]}"
            else:
                display_regex = f"{_V1_PREFIX}{pattern}"
            yield route, f"{_V1_PREFIX}{route.path}", display_regex

_METHOD_ORDER = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
_METHOD_COLORS = {
    'GET': '\033[32m',      # green
    'HEAD': '\033[36m',     # cyan
    'POST': '\033[33m',     # yellow
    'PUT': '\033[34m',      # blue
    'PATCH': '\033[35m',    # magenta
    'DELETE': '\033[31m',   # red
    'OPTIONS': '\033[37m',  # white
}
_COLOR_RESET = '\033[0m'

def _sorted_methods(data):
    methods = getattr(data, 'methods', None) or set()
    ordered = [m for m in _METHOD_ORDER if m in methods]
    ordered += sorted(methods - set(_METHOD_ORDER))
    return ordered

def _method_label(data):
    return '/'.join(_sorted_methods(data))

def _method_color(data):
    methods = _sorted_methods(data)
    return _METHOD_COLORS.get(methods[0], '') if methods else ''

def list_all_endpoints(filter_str=''):
    max_name = 50
    max_path = 50
    max_reg = 50
    max_method = len('Method')

    def _roles(depend):
        raw_roles = getattr(depend, 'roles', '')
        if not raw_roles:
            return ''
        roles = []
        for role in raw_roles:
            roles.append(role.replace('administrator', 'adm'))
        return ';'.join(roles)

    routes = list(_iter_effective_routes())

    for data, path, regex in routes:
        if len(path) > max_path:
            max_path = len(path)
        if len(data.name) > max_name:
            max_name = len(data.name)
        if len(regex) > max_reg:
            max_reg = len(regex)
        if len(_method_label(data)) > max_method:
            max_method = len(_method_label(data))

    print("-"*(max_reg+max_path+max_name+max_method+70))
    print(f"{"Method":{max_method}} | {"URL":{max_path}} | {"Desc.":{max_name}} | {"Regexp":{max_reg}} | {'Roles'}")
    print("-"*(max_reg+max_path+max_name+max_method+70))
    for data, path, regex in routes:
        dependant = getattr(data, 'dependant', None)
        method = _method_label(data)
        color = _method_color(data)
        method_field = f"{method:{max_method}}"
        method_field = f"{color}{method_field}{_COLOR_RESET}" if color else method_field

        if dependant and dependant.dependencies:
            line = f"{path:{max_path}} | {data.name:{max_name}} | {regex:{max_reg}} | {_roles(dependant.dependencies[0].call)}"
        else:
            line = f"{path:{max_path}} | {data.name:{max_name}} | {' '*max_reg} |"

        if filter_str in line:
            print(f"{method_field} | {line}")

    print("-"*(max_reg+max_path+max_name+max_method+70))

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

    check_tmp_dir()

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
