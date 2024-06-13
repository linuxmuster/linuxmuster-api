from fastapi import Depends, Request, HTTPException
from starlette import status

from .header import *
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


class BasicChecker:
    """
    Root class which defines all common functions and variables for the other checker.
    This class can not be used directly, its only purpose is code factoring.
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

            if not requested_user:
                return False

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

class RoleChecker(BasicChecker):
    """
    Check role for permission access. Missing the possibility to check the user:
    globaladmin can access all user informations, but an user should be able to
    access its own informations.
    """

    def __init__(self, roles) -> None:
        BasicChecker.__init__(self, roles)

    def __call__(self, who: AuthenticatedUser = Depends(check_authentication_header)) -> AuthenticatedUser:

        if who.role == 'globaladministrator':
            return who

        if who.role in self.roles:
            return who

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Permissions denied')


class UserChecker(BasicChecker):
    """
    Check role and user for permission access.
    globaladmin can access all user informations, and an user is able to access its own informations.
    """

    def __init__(self, roles) -> None:
        BasicChecker.__init__(self, roles)

    def __call__(self, who: AuthenticatedUser = Depends(check_authentication_header), user=None) -> AuthenticatedUser:

        if who.role == 'globaladministrator':
            return who

        if who.user == user:
            return who

        if who.role in self.roles and self._check_role_permissions(who, user):
            return who

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Permissions denied')


class UserListChecker(BasicChecker):
    """
    Check role and user for permission access for command that need to be run over several users.
    globaladmin can access all user informations, and an user is able to access its own informations, and to access
    informations of users from a bellow roles.
    """

    def __init__(self, roles) -> None:
        BasicChecker.__init__(self, roles)

    async def __call__(self, request: Request, who: AuthenticatedUser = Depends(check_authentication_header)) -> bool:

        body = await request.json()
        users = body.get('users', [])

        if who.role == 'globaladministrator':
            return who

        if who.role in self.roles:
            # If one user has higher level, refuse to answer
            for user in users:
                if not self._check_role_permissions(who, user):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail='Permissions denied'
                    )
            return who

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Permissions denied')