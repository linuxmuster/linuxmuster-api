from fastapi import Depends, HTTPException
from starlette import status

from .header import *
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


class UserChecker:
    """
    Check role and user for permission access.
    globaladmin can access all user informations, and an user is able to access its own informations.
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

            identity = who.user
            identity_role = who.role

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

    def __call__(self, who: AuthenticatedUser = Depends(check_authentication_header), user=None) -> bool:

        if who.role == 'globaladministrator':
            return who

        if who.user == user:
            return who

        if who.role in self.roles and self._check_role_permissions(who, user):
            return who

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Permissions denied'
        )
