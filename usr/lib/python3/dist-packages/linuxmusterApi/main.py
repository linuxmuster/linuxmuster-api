#! /usr/bin/env python3

import time
import uvicorn
import yaml
import os
import sys
import base64
import binascii
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware


config = {}
config_path = '/etc/linuxmuster/api/config.yml'
if os.path.isfile(config_path):
    with open(config_path, 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.SafeLoader)

app = FastAPI(swagger_ui_parameters={"tryItOutEnabled": True})

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
    query,
    managementgroups,
    projects,
    roles,
    schoolclasses,
    sessions,
    teachers,
    users,
)

app.include_router(auth.router, prefix="/v1")
app.include_router(exam.router, prefix="/v1")
app.include_router(query.router, prefix="/v1")
app.include_router(managementgroups.router, prefix="/v1")
app.include_router(projects.router, prefix="/v1")
app.include_router(schoolclasses.router, prefix="/v1")
app.include_router(sessions.router, prefix="/v1")
app.include_router(roles.router, prefix="/v1")
app.include_router(teachers.router, prefix="/v1")
app.include_router(users.router, prefix="/v1")

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
    """Default response at /"""

    return """
<html>
    <head>
        <title>Linuxmuster-api</title>
    </head>
    <body>
        <h1>Empty response</h1>
    </body>
</html>
    """

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

    uvicorn.run("main:app", **config['uvicorn'])
