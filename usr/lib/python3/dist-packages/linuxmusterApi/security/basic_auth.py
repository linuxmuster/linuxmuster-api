from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBasicCredentials
from starlette import status
import jwt
import base64
import yaml
from typing_extensions import Annotated

from linuxmusterTools.ldapconnector import LMNLdapReader as lr


X_API_KEY = APIKeyHeader(name='X-API-Key')
BASIC_AUTH = HTTPBasic()

def generate_jwt(user):
    """
    Generate a valid jwt for a specific user.

    :param user: concerned user
    :type user: basestring
    :return: jwt
    :rtype: basestring
    """

    user_details = lr.get(f'/users/{user}')
    if not user_details:
        # User not found in ldap tree, discarding request
        return ''

    with open('/etc/linuxmuster/api/config.yml', 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.SafeLoader)

    secret = base64.b64decode(config['secret'])

    payload  = {
        'user': user,
        'role': user_details['sophomorixRole'],
        'school': user_details['sophomorixSchoolname']
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
        user = lr.get(f'/users/{credentials.username}', dict=False)
        if user.test_password(password=credentials.password):
            return generate_jwt(user.cn)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Wrong credentials, please send a valid username and password.'
        )