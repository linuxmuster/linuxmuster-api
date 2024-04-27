from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader
from starlette import status
import jwt
import base64
import yaml
from pydantic import BaseModel

from linuxmusterTools.ldapconnector import LMNLdapReader as lr


class AuthenticatedUser(BaseModel):
    user: str
    role: str | None = None
    school: str | None = None


X_API_KEY = APIKeyHeader(name='X-API-Key')

def check_authentication_header(x_api_key: str = Depends(X_API_KEY)) -> AuthenticatedUser:
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
    user_details = lr.getvalues(f'/users/{user}', ['sophomorixRole','sophomorixSchoolname'])

    return AuthenticatedUser(
        user=user,
        role=user_details['sophomorixRole'],
        school=user_details['sophomorixSchoolname']
    )

