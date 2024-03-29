from fastapi import Depends, HTTPException
from starlette import status

from .header import check_authentication_header


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

    def __call__(self, who: dict = Depends(check_authentication_header)) -> bool:

        if who["role"] == 'globaladministrator':
            return True

        if who["role"] in self.roles:
            return True

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Permissions denied'
        )
