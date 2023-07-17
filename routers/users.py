from fastapi import APIRouter, Depends, HTTPException

from security import check_authentication_header
from utils import lmn_getSophomorixValue


router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(check_authentication_header)],
    responses={404: {"description": "Not found"}},
)

@router.get("/")
def get_all_users():
    return "ALL"

@router.get("/{user}")
def get_user_details(user: str):
    cmd = f"sophomorix-user -ivvv -u {user} -jj".split()
    return lmn_getSophomorixValue(cmd, '')