from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse

from routers import users


app = FastAPI()

app.include_router(users.router)

@app.get("/", response_class=HTMLResponse)
def read_root():
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

