import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from security import RoleChecker, UserListChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNLdapWriter as lw


router = APIRouter(
    prefix="/managementgroups",
    tags=["Management Groups"],
    responses={404: {"description": "Not found"}},
)

class UserList(BaseModel):
    users: list | None = None

@router.get("/")
def get_management_groups_list(who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    List the samba management group an user can modify.
    """

    return [group['cn'] for group in lr.get('/managementgroups', attributes=['cn'])]

@router.get("/{group}")
def get_group_details(group: str, auth: bool = Depends(RoleChecker("GS"))):
    """
    Get informations a bout a specific management group.
    """

    group_details = lr.get(f'/managementgroups/{group}')

    if group_details:
        return group_details

    raise HTTPException(status_code=404, detail=f"Management group {group} not found.")

@router.delete("/{group}/members", status_code=204)
def remove_user_from_group(group: str, userlist: UserList, who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    Remove users from a specific management group.

    :param group: group name
    :type group: basestring
    :param users: users list
    :type users: list
    """

    if not userlist.users:
        # Nothing to do
        return

    group_details = lr.get(f'/managementgroups/{group}')

    if not group_details:
        raise HTTPException(status_code=404, detail=f"Management group {group} not found.")

    for member in userlist.users:
        dn = lr.getval(f'/users/{member}', 'dn')
        if dn:
            lw.delete(group, 'group', {'member': dn})
        else:
            logging.warning(f"User {member} not found, will not delete from management group {group}")

    return

@router.post("/{group}/members")
def add_user_to_group(group: str, userlist: UserList, who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    Add users to a specific management group.

    :param group: group name
    :type group: basestring
    :param users: users list
    :type users: list
    """

    if not userlist.users:
        # Nothing to do
        return

    group_details = lr.get(f'/managementgroups/{group}')

    if not group_details:
        raise HTTPException(status_code=404, detail=f"Management group {group} not found.")

    for member in userlist.users:
        dn = lr.getval(f'/users/{member}', 'dn')
        if dn:
            lw.set(group, 'group', {'member': dn}, add=True)
        else:
            logging.warning(f"User {member} not found, will not add it to management group {group}")

    return
