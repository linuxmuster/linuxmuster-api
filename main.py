import time
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse

from routers import users, sessions, query


app = FastAPI()

app.include_router(users.router)
app.include_router(sessions.router)
app.include_router(query.router)

@app.middleware("http")
async def add_process_time_logging(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

@app.get("/", response_class=HTMLResponse)
def root_response():
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

