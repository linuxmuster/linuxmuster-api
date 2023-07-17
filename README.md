# linuxmuster-api

Sample test repository for deploying a linuxmuster API via FastAPI.

To start the server, simply do a:

    uvicorn main:app --root-path PATH --reload --host 0.0.0.0 --ssl-keyfile /etc/ajenti/key.pem --ssl-certfile /etc/ajenti/cert.pem

It will then listen on port 8000 and you can reach the Swagger UI at https://server:8000/docs