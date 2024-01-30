from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from security import PermissionChecker
from utils import lmn_getSophomorixValue


router = APIRouter(
    prefix="/managementgroups",
    tags=["Management Groups"],
    responses={404: {"description": "Not found"}},
)

class UsersList(BaseModel):
    users: list | None = None

@router.get("/")
def get_management_groups_list(auth: bool = Depends(PermissionChecker("globaladministrator"))):
    # Yes, it's not pretty good ... I must find a better way to list all available groups
    groups = ['wifi', 'internet', 'intranet', 'webfilter', 'printing']
    return groups + [f'no{g}' for g in groups]

@router.get("/groups/{group}")
def get_group_details(group: str, auth: bool = Depends(PermissionChecker("globaladministrator"))):
    cmd = f"sophomorix-managementgroup -i -m {group} -jj".split()
    return lmn_getSophomorixValue(cmd, f'GROUPS/{group}')

@router.delete("/groupmembership/{group}")
def remove_user_from_group(group: str, usersList: UsersList, auth: bool = Depends(PermissionChecker("globaladministrator"))):
    cmd = ['sophomorix-managementgroup', f'--no{group}', ','.join(usersList.users), '-jj']
    return lmn_getSophomorixValue(cmd, '')

@router.post("/groupmembership/{group}")
def add_user_to_group(group: str, usersList: UsersList, auth: bool = Depends(PermissionChecker("globaladministrator"))):
    cmd = ['sophomorix-managementgroup', f'--{group}', ','.join(usersList.users), '-jj']
    return lmn_getSophomorixValue(cmd, '')