from fastapi import APIRouter, Depends, HTTPException

from security import check_authentication_header
from utils import lmn_getSophomorixValue


router = APIRouter(
    prefix="/query",
    tags=["query"],
    dependencies=[Depends(check_authentication_header)],
    responses={404: {"description": "Not found"}},
)

@router.get("/{school}/{role}/{sam}")
def query_user(role: str, school: str='default-school', sam: str=''):
    if sam:
        sam = f"--sam {sam}"
    cmd = f"sophomorix-query --{role} --schoolbase {school} --user-full {sam} -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.get("/{school}/{role}")
def query_role(role: str, school: str='default-school'):
    cmd = f"sophomorix-query --{role} --schoolbase {school} --user-full -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.get("/globaladministrator")
def query_role():
    cmd = f"sophomorix-query --globaladministrator --user-full -jj".split()
    return lmn_getSophomorixValue(cmd, '')