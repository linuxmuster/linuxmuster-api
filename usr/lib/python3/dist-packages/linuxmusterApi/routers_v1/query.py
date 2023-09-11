from fastapi import APIRouter, Depends, HTTPException

from security import PermissionChecker
from utils import lmn_getSophomorixValue


router = APIRouter(
    prefix="/query",
    tags=["Query"],
    responses={404: {"description": "Not found"}},
)

@router.get("/{school}/{role}/{sam}")
def query_user(role: str, school: str='default-school', sam: str='', auth: bool = Depends(PermissionChecker("globaladministrator"))):
    if sam:
        sam = f"--sam {sam}"
    cmd = f"sophomorix-query --{role} --schoolbase {school} --user-full {sam} -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.get("/{school}/{role}")
def query_role(role: str, school: str='default-school', auth: bool = Depends(PermissionChecker("globaladministrator"))):
    cmd = f"sophomorix-query --{role} --schoolbase {school} --user-full -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.get("/globaladministrator")
def query_role(auth: bool = Depends(PermissionChecker("globaladministrator"))):
    cmd = f"sophomorix-query --globaladministrator --user-full -jj".split()
    return lmn_getSophomorixValue(cmd, '')