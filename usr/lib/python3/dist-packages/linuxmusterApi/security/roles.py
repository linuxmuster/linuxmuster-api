from fastapi import Depends, HTTPException
from starlette import status

from .header import *

# + Owner of group ?
class RoleChecker:
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

    def __call__(self, who: AuthenticatedUser = Depends(check_authentication_header)) -> AuthenticatedUser:

        if who.role == 'globaladministrator':
            return who

        if who.role in self.roles:
            return who

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Permissions denied'
        )
