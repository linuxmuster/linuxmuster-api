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


config = {}
config_path = '/etc/linuxmuster/api/config.yml'
if os.path.isfile(config_path):
    with open(config_path, 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.SafeLoader)

description = """

This API provides access to a [linuxmuster.net](http://www.linuxmuster.net/)'s server management, like listing schoolclasses, users, starting an exam, etc ...

### Security

The endpoints are per role and user secured. Each request MUST provide a valid **JWT (JSON Web Token)** in the header (key `X-Api-Key`) to get the data.

In order to get a valid JWT, you first need to send username and password via Basic auth at the endpoint [https://SERVER:8001/v1/auth](/v1/auth).

### First request

You are yet so far to launch your first request, just send a GET request with your JWT to [https://SERVER:8001/v1/schoolclasses](/v1/schoolclasses) and you will get a whole list of all schoolclasses on the server ! Have fun with it :)
"""

app = FastAPI(
    title = "Linuxmuster.net API",
    version="7.2.18",
    description = description,
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
    auth,
    exam,
    groups,
    query,
    managementgroups,
    print_passwords,
    printers,
    projects,
    roles,
    samba,
    schoolclasses,
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

    return """
<html>
    <head>
        <title>Linuxmuster.net API</title>
    </head>
    <body>
        <h1>Linuxmuster.net API</h1>
        <p>Please refer to the <a href="docs/">documentation</a> to use this API</p>
    </body>
</html>
    """

app.include_router(auth.router, prefix="/v1")
app.include_router(roles.router, prefix="/v1")
app.include_router(users.router, prefix="/v1")
app.include_router(teachers.router, prefix="/v1")
app.include_router(query.router, prefix="/v1")
app.include_router(schoolclasses.router, prefix="/v1")
app.include_router(managementgroups.router, prefix="/v1")
app.include_router(projects.router, prefix="/v1")
app.include_router(groups.router, prefix="/v1")
app.include_router(sessions.router, prefix="/v1")
app.include_router(exam.router, prefix="/v1")
app.include_router(samba.router, prefix="/v1")
app.include_router(print_passwords.router, prefix="/v1")
app.include_router(printers.router, prefix="/v1")

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
