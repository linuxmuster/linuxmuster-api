from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/roles",
    tags=["Roles"],
    responses={404: {"description": "Not found"}},
)

# TODO: structure/sort inconsistency — returns an unsorted set() of strings, while
# GET /devices/roles (same kind of data: list of role names) returns a sorted list.
# Keep this out of /users (scope is users+devices via /search/, unlike /roles/{role}).
@router.get("/", name="List all existing roles")
def get_all_roles(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## List all existing roles including users and computers

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

# TODO: structure inconsistency — returns list[dict] (full user objects) while GET /roles/
# returns list[str] (role names), under the same router. Scope is users-only
# (objectClass=user) unlike /roles/: should move to /users/roles/{role} (breaking change,
# check webui7/cli7 callers first). check_parents also switches the response schema
# (LMNUserModel vs LMNRawUserModel) without this being visible in OpenAPI (no response_model).
@router.get("/{role}", name="List all members with a specific role")
def get_role_users(role: str, check_parents: bool = False, school: str | None = None, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## List all users (and all their details) having a specific role

    The given role can be teacher, student, globaladministrator, etc ...

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param role: The role to request (student, schooladministrator, etc...)
    :type role: basestring
    :param school: The school where to get the users. A school-administrator
    may only name their own, and gets it by default; default-school is the
    default for a global-administrator
    :type school: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List with all informations of all users with this role (as dict)
    :rtype: list
    """


    if who.school != 'global':
        if school and school != who.school:
            raise HTTPException(
                status_code=403,
                detail="school-administrators can only read their own school."
            )

        school = who.school

    if check_parents:
        endpoint = 'roles'
    else:
        endpoint = 'rawroles'

    if role.startswith('global'):
        if who.school != 'global':
            raise HTTPException(
                status_code=403,
                detail=f"Only global-administrators can list the {role}s."
            )

        return lr.get(f'/{endpoint}/{role}')

    # A global-administrator naming no school reads default-school, as before.
    return lr.get(f'/{endpoint}/{role}', school=school or 'default-school')

