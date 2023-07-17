from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse

from routers import users, sessions


app = FastAPI()

app.include_router(users.router)
app.include_router(sessions.router)

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

