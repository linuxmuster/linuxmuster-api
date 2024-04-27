from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from security import RoleChecker, UserListChecker
from sophomorix import lmn_getSophomorixValue
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/managementgroups",
    tags=["Management Groups"],
    responses={404: {"description": "Not found"}},
)

class UserList(BaseModel):
    users: list | None = None

@router.get("/")
def get_management_groups_list(auth: bool = Depends(RoleChecker("GST"))):
    """
    List the samba group an user can modify.
    """

    return [group['cn'] for group in lr.get('/managementgroups', attributes=['cn'])]

@router.get("/{group}")
def get_group_details(group: str, auth: bool = Depends(RoleChecker("GS"))):
    """
    Get informations a bout a specific group.
    """

    return lr.get(f'/managementgroups/{group}')

@router.delete("/groupmembership/{group}")
def remove_user_from_group(group: str, userlist: UserList, auth: bool = Depends(UserListChecker("GST"))):
    """
    Remove users from a specific group.

    :param group: group name
    :type group: basestring
    :param users: users list
    :type users: list
    """

    cmd = ['sophomorix-managementgroup', f'--no{group}', ','.join(userlist.users), '-jj']
    return lmn_getSophomorixValue(cmd, '')

@router.post("/groupmembership/{group}")
def add_user_to_group(group: str, userlist: UserList, auth: bool = Depends(UserListChecker("GST"))):
    """
    Add users to a specific group.

    :param group: group name
    :type group: basestring
    :param users: users list
    :type users: list
    """

    cmd = ['sophomorix-managementgroup', f'--{group}', ','.join(userlist.users), '-jj']
    return lmn_getSophomorixValue(cmd, '')
