from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, UserListChecker, AuthenticatedUser
from .body_schemas import UserList
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.samba_util import GroupManager
from utils.checks import require_school


router = APIRouter(
    prefix="/managementgroups",
    tags=["Management Groups"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="List all samba management groups")
def get_management_groups_list(who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List all available samba management groups.

    Return the cn of the found groups.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param user: Valid LDAP samaccountname
    :type user: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List cn of each management group
    :rtype: list
    """


    return lr.getval('/managementgroups', 'cn', school=who.school)

@router.get("/{group}", name="Get details of a specific management group")
def get_group_details(group: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## List all informations of a specific samba management group.

    The details returned are *members*, *cn*, *sophomorixSchoolName*, *dn*,
    etc...

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: Valid cn of a management group
    :type group: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All available informations
    :rtype: dict
    """


    group_details = lr.get(f'/managementgroups/{group}', school=who.school)

    if group_details:
        return group_details

    raise HTTPException(status_code=404, detail=f"Management group {group} not found.")

@router.delete("/{group}/members", status_code=204, name="Remove users from a specific management group")
@require_school
def remove_user_from_group(group: str, userlist: UserList, school: str = '', who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    ## Remove members from a specific management group.

    `group` is the bare group name (e.g. "wifi"), never school-prefixed:
    the school-specific LDAP cn (e.g. "secondary-wifi") is resolved from
    `school`/`who.school`.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param group: Bare name of a management group (e.g. "wifi", "internet")
    :type group: basestring
    :param userlist: List of samaccountname to remove
    :type userlist: UserList
    :param school: School to operate on. Required for global-administrators,
                   who are not scoped to a single school.
    :type school: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if "admins" in group and who.role == "teacher":
        raise HTTPException(status_code=403, detail=f"User {who.user} not allowed to modify group {group}.")

    if not userlist.users:
        # Nothing to do
        raise HTTPException(status_code=400, detail=f"Missing userlist of members to delete")

    active_school = school if school else who.school

    try:
        GroupManager(school=active_school).remove_members(group, userlist.users)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    return

@router.post("/{group}/members", name="Add users to a specific management group")
@require_school
def add_user_to_group(group: str, userlist: UserList, school: str = '', who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    ## Add members to a specific management group.

    `group` is the bare group name (e.g. "wifi"), never school-prefixed:
    the school-specific LDAP cn (e.g. "secondary-wifi") is resolved from
    `school`/`who.school`.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data and students)

    \f
    :param group: Bare name of a management group (e.g. "wifi", "internet")
    :type group: basestring
    :param userlist: List of samaccountname to add
    :type userlist: UserList
    :param school: School to operate on. Required for global-administrators,
                   who are not scoped to a single school.
    :type school: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if "admins" in group and who.role == "teacher":
        raise HTTPException(status_code=403, detail=f"User {who.user} not allowed to modify group {group}.")

    if not userlist.users:
        # Nothing to do
        raise HTTPException(status_code=400, detail=f"Missing userlist of members to add")

    active_school = school if school else who.school

    try:
        GroupManager(school=active_school).add_members(group, userlist.users)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    return
