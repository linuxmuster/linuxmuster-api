from fastapi import APIRouter, Depends, HTTPException

from security import check_authentication_header
from utils import lmn_getSophomorixValue


router = APIRouter(
    prefix="/sessions",
    tags=["sessions"],
    dependencies=[Depends(check_authentication_header)],
    responses={404: {"description": "Not found"}},
)

@router.get("/per_supervisor/{supervisor}")
def session_supervisor(supervisor: str, auth: dict = Depends(check_authentication_header)):
    cmd = f"sophomorix-session -i --supervisor {supervisor} -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.get("/{session}")
def get_session_sessionname(session: str, auth: dict = Depends(check_authentication_header)):
    cmd = f"sophomorix-session -i --session {session} -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.delete("/{session}")
def delete_session(session: str, auth: dict = Depends(check_authentication_header)):
    cmd = f"sophomorix-session --session {session} --kill -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.post("/session/{supervisor}/{sessionname}")
def session_create(supervisor: str, sessionname: str, auth: dict = Depends(check_authentication_header)):
    cmd = f"sophomorix-session --create --supervisor {supervisor} --comment {sessionname} -jj".split()
    return lmn_getSophomorixValue(cmd, '')