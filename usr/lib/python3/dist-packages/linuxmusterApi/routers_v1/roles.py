from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/roles",
    tags=["Roles"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="List all existing roles")
def get_all_roles(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## List all existing roles

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all roles
    :rtype: list
    """


    return set([k['sophomorixRole'] for k in lr.get('/search/', attributes=['sophomorixRole']) if k['sophomorixRole']])

@router.get("/{role}", name="List all members with a specific role")
def get_role_users(role: str, school: str | None = 'default-school', who: AuthenticatedUser = Depends(RoleChecker(["GS"]))):
    """
    ## List all users (and all their details) having a specific role

    The given role can be teacher, student, globaladministrator, etc ...

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param role: The role to request (student, schooladministrator, etc...)
    :type role: basestring
    :param school: The school where to get the users
    :type school: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List with all informations of all users with this role (as dict)
    :rtype: list
    """


    if 'global' in role:
        return lr.get(f'/roles/{role}')

    return lr.get(f'/roles/{role}', school=school)

