from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader
from starlette import status
import jwt
import base64
import yaml

from linuxmusterTools.ldapconnector import LMNLdapReader as lr


X_API_KEY = APIKeyHeader(name='X-API-Key')

def check_authentication_header(x_api_key: str = Depends(X_API_KEY)):
    """
    Return role associated with the api key.
    """

    with open('/etc/linuxmuster/api/config.yml', 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.SafeLoader)

    secret = base64.b64decode(config['secret'])

    try:
        payload = jwt.decode(x_api_key, secret, algorithms=["HS512", "HS256"])
        user = payload['user']
    except (jwt.exceptions.InvalidSignatureError, jwt.exceptions.DecodeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )

    # No memory leak
    secret = ''

    # role may be eventually None
    return {
        "user": user,
        "role": lr.getval(f'/users/{user}', 'sophomorixRole')
    }

