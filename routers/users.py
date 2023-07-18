from fastapi import APIRouter, Depends, HTTPException, Request
import subprocess

from security import PermissionChecker
from utils import lmn_getSophomorixValue


router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)

@router.get("/")
def get_all_users(auth: bool = Depends(PermissionChecker("globaladministrator"))):
    return "ALL"

@router.get("/{user}")
def get_user_details(user: str, auth: bool = Depends(PermissionChecker(["schooladministrator", "globaladministrator"]))):
    cmd = f"sophomorix-user -ivvv -u {user} -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.post("/testrootperm")
def test_root_perm(auth: bool = Depends(PermissionChecker(["student"]))):
    cmd = f"touch /root/testapi.log".split()
    subprocess.check_call(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    return "ok"