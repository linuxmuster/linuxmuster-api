from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker
from utils import lmn_getSophomorixValue


router = APIRouter(
    prefix="/sessions",
    tags=["Sessions"],
    responses={404: {"description": "Not found"}},
)

# TODO: rewrite the whole with lr and lw
# TODO: Permissions

@router.get("/per_supervisor/{supervisor}")
def session_supervisor(supervisor: str, auth: bool = Depends(RoleChecker("GS"))):
    cmd = f"sophomorix-session -i --supervisor {supervisor} -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.get("/{session}")
def get_session_sessionname(session: str, auth: bool = Depends(RoleChecker("GS"))):
    cmd = f"sophomorix-session -i --session {session} -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.delete("/{session}")
def delete_session(session: str, auth: bool = Depends(RoleChecker("GS"))):
    cmd = f"sophomorix-session --session {session} --kill -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.post("/session/{supervisor}/{sessionname}")
def session_create(supervisor: str, sessionname: str, auth: bool = Depends(RoleChecker("GS"))):
    cmd = f"sophomorix-session --create --supervisor {supervisor} --comment {sessionname} -jj".split()
    return lmn_getSophomorixValue(cmd, '')