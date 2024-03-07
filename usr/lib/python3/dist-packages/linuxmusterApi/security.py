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

async def generate_jwt(user):
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
    }

    token = jwt.encode(payload, secret, algorithm="HS512")

    # No memory leak
    secret = ''

    return token

async def check_authentication_header(x_api_key: str = Depends(X_API_KEY)):
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

class PermissionChecker:
    """
    Check role for permission access. Missing the possibility to check the user:
    globaladmin can access all user informations, but an user should be able to
    access its own informations.
    """

    ROLES_MAPPING = {
        'G': 'globaladministrator',
        'S': 'schooladministrator',
        'T': 'teacher',
        's': 'student'
    }

    def __init__(self, roles) -> None:
        if isinstance(roles, list):
            self.roles = roles
        elif isinstance(roles, str):
            self.roles = [
                self.ROLES_MAPPING[alias]
                for alias in roles if alias in self.ROLES_MAPPING
            ]


    def _check_role_permissions(self, who, requested_user):

            role_rank = {
                'globaladministrator': 4,
                'schooladministrator': 3,
                'teacher': 2,
                'student': 1,
                'examuser': 1,
            }

            identity = who['user']
            identity_role = who['role']

            # Global admins have all rights
            if identity_role == 'globaladministrator':
                return True

            if requested_user.endswith('-exam'):
                user_role = "examuser"
            else:
                user_role = lr.getval(f'/users/{requested_user}', 'sophomorixRole')

            ## Some additional security checks
            # Access forbidden for students
            if identity_role not in ['teacher', 'schooladministrator']:
                return False

            # Same role but other user -> access forbidden
            if identity_role == user_role:
                # User can only change its own password, not from someone else with the same role
                if identity != requested_user:
                    return False
            else:
                # Check if the role rank of the user is greater than the user logged in
                # If the role of the user can not be found, access forbidden
                if role_rank.get(user_role, 5) > role_rank[identity_role]:
                    return False

            return True

    def __call__(self, who: dict = Depends(check_authentication_header), user=None) -> bool:

        if who["role"] in self.roles or who["role"] == 'globaladministrator':
            return True

        if who["user"] == user:
            return True

        if self._check_role_permissions(who, user):
            return True

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Permissions denied'
        )

class BasicAuthChecker:
    """
    Check username and password from basic auth.
    """

    async def __call__(self, credentials: Annotated[HTTPBasicCredentials, Depends(BASIC_AUTH)]) -> str:
        user = lr.get(f'/users/{credentials.username}', dict=False)
        if user.test_password(password=credentials.password):
            return await generate_jwt(user.cn)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Wrong credentials, please send a valid username and password.'
        )
