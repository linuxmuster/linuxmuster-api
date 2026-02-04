VERSION = "7.3.26"
TITLE = "Linuxmuster.net API"

DESCRIPTION = """

This API provides access to a [linuxmuster.net](http://www.linuxmuster.net/)'s server management, like listing schoolclasses, users, starting an exam, etc ...
## Security

### Firewall

⚠️ In his default configuration, `linuxmuster-api` listen on port 8001. Since the API can provide sensitive information, it's **very important** to restrict the access to this port to only the clients or machines who need it.

### Authentication

The endpoints are per role and per user secured. 
Each request MUST provide a valid **JWT (JSON Web Token)** in the header (key `X-Api-Key`) to get the data.

An user can get a valid JWT token by sending username and password via Basic auth at the endpoint https://SERVER:8001/v1/auth.

## First request

You are yet so far to launch your first request, just send a GET request with your JWT to [https://SERVER:8001/v1/schoolclasses](/v1/schoolclasses) and you will get a whole list of all schoolclasses on the server ! Have fun with it :)
"""

HTML_HOME = f"""
<html>
    <head>
        <title>Linuxmuster.net API {VERSION}</title>
    </head>
    <body>
        <h1>Linuxmuster.net API {VERSION}</h1>
        <p>Please refer to the <a href="docs/">documentation</a> to use this API</p>
    </body>
</html>
    """
