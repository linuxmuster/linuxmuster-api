import time
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse


app = FastAPI(swagger_ui_parameters={"tryItOutEnabled": True})

# V1
from routers_v1 import users, sessions, query

app.include_router(users.router, prefix="/v1")
app.include_router(sessions.router, prefix="/v1")
app.include_router(query.router, prefix="/v1")

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

