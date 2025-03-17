from fastapi import Depends, HTTPException, Request
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
X_HOST_KEY = APIKeyHeader(name='X-HOST-Key')

def check_authentication_header(request: Request) -> AuthenticatedUser:
    """
    Return role associated with the api key.
    """


    apikey = request.headers.get('x-api-key', None)
    hostkey = request.headers.get('x-host-key', None)

    if apikey and hostkey:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only one header Key is accepted",
        )

    if apikey:
        return check_user_header(apikey)

    if hostkey:
        return check_host_header(hostkey)

    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )

def check_user_header(apikey) -> AuthenticatedUser:

    with open('/etc/linuxmuster/api/config.yml', 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.SafeLoader)

    secret = base64.b64decode(config['secret'])

    try:
        payload = jwt.decode(apikey, secret, algorithms=["HS512", "HS256"])
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

    if user_details.get('sophomorixRole', None) is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )

    return AuthenticatedUser(
        user=user,
        role=user_details['sophomorixRole'],
        school=user_details.get('sophomorixSchoolname', "")
    )


def check_host_header(hostkey) -> AuthenticatedUser:

    with open('/etc/linuxmuster/api/config.yml', 'r') as config_file:
        keys = yaml.load(config_file, Loader=yaml.SafeLoader).get('host_keys', {})

    if hostkey in keys:
        user = keys[hostkey]['user']

    # No memory leak
    keys = ''

    # role may be eventually None
    user_details = lr.getvalues(f'/users/{user}', ['sophomorixRole','sophomorixSchoolname'])

    if user_details.get('sophomorixRole', None) is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )

    return AuthenticatedUser(
        user=user,
        role=user_details['sophomorixRole'],
        school=user_details.get('sophomorixSchoolname', "")
    )