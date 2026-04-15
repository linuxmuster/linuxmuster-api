from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBasicCredentials
from starlette import status
import jwt
import base64
import yaml
from datetime import datetime, timezone, timedelta
from typing_extensions import Annotated

from linuxmusterTools.ldapconnector import LMNLdapReader as lr


BASIC_AUTH = HTTPBasic()

def generate_jwt(user, role, dn, school):
    """
    Generate a valid jwt for a specific user.

    :return: jwt
    :rtype: basestring
    """


    with open('/etc/linuxmuster/api/config.yml', 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.SafeLoader)

    secret = base64.b64decode(config['secret'])

    payload  = {
        'exp': datetime.now(timezone.utc) + timedelta(hours=12),
        'user': user,
        'role': role,
        'dn': dn,
        'school': school
    }

    token = jwt.encode(payload, secret, algorithm="HS512")

    # No memory leak
    secret = ''

    return token

class BasicAuthChecker:
    """
    Check username and password from basic auth.
    """


    def __call__(self, credentials: Annotated[HTTPBasicCredentials, Depends(BASIC_AUTH)]) -> str:
        try:
            user = lr.get(f'/users/{credentials.username}', dict=False)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Malformated username, please send a valid username and password.'
            )

        if user.test_password(password=credentials.password):
            return generate_jwt(user.cn, user.sophomorixRole, user.dn, user.sophomorixSchoolname)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Wrong credentials, please send a valid username and password.'
        )
