# linuxmuster-api

Linuxmuster API is the main evolution for the next linuxmuster.net's server, version 8.
Based on the wonderful [FastAPI](https://fastapi.tiangolo.com/), it will give the possibility to let other software to interact with the data and tools provided by the linuxmuster.net's server.

## Installation

Simply install the package `linumxuster-api7` from our [deb repository](https://github.com/linuxmuster/deb).
Beware: this package is only published for developing purpose, DON'T USE IT ON A 7.2 PRODUCTION SERVER.

After the installation, the `uvicorn` server should start automatically ans listen on port 8001.
You can manage it via `systemctl`:

    systemctl start linuxmuster-api
    systemctl stop linuxmuster-api

## Configuration

Some configurations options are stored in `/etc/linuxmuster/api/config.yml`:

  * uvicorn:
    * port: 8001 (default)
    * host: 0.0.0.0 (default)
    * ssl_certfile: /etc/linuxmuster/api/lmnapi.pem (self-signed, default)
    * ssl_keyfile: /etc/linuxmuster/api/lmnapi.pem (self-signed, default)
    * log_level: info (default)
  * secret: secret key generated by the install process in order to generate JWT tokens, keep it secret.

## First steps

FastApi provides two convenients ways to play with the API:

  * https://SERVER:8001/docs : Swagger UI, you can see all endpoints and interact directly with all of these
  * https://SERVER:8001/redoc: Full documentation about all endpoints.

### Security

The endpoints are per role secured. For the moment, only global administrators have enough permissions to use most of the endpoints, but it's in constant evolution. Each request MUST provide a valid JWT token in the header (key `X-Api-Key`) to get the data.

You can get a valid JWT token by sending username and password via Basic auth at the endpoint https://SERVER:8001/v1/auth.

### First request

You are yet so far to lmaunch your first request, just send a GET request with your JWT to https://SERVER:8001/v1/schoolclasses and you will get a whole list of all schoolclasses on the server ! Have fun with it :)

## Development

This project is pretty young and there's many room for improvement:

  * add a correct and complete endpoint map,
  * add all necessary endpoint to provide enough flexibility,
  * correctly handle all type of errors (500, 401, 404, ...),
  * set the permissions correctly,
  * and many more ... any help is welcome.