from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from security import RoleChecker, UserListChecker
from utils import lmn_getSophomorixValue


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

    # Yes, it's not pretty good ... I must find a better way to list all available groups
    groups = ['wifi', 'internet', 'intranet', 'webfilter', 'printing']
    return groups + [f'no{g}' for g in groups]

@router.get("/groups/{group}")
def get_group_details(group: str, auth: bool = Depends(RoleChecker("GS"))):
    """
    Get informations a bout a specific group.
    """

    cmd = f"sophomorix-managementgroup -i -m {group} -jj".split()
    return lmn_getSophomorixValue(cmd, f'GROUPS/{group}')

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