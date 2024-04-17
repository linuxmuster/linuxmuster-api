from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker
from utils import lmn_getSophomorixValue
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/sessions",
    tags=["Sessions"],
    responses={404: {"description": "Not found"}},
)

# TODO: rewrite the whole with lr and lw
# TODO: Permissions

@router.get("/{supervisor}")
def session_supervisor(supervisor: str, auth: bool = Depends(RoleChecker("GS"))):
    sessions = lr.get(f'/users/{supervisor}', dict=False).lmnsessions
    sessionsList = []
    for session in sessions:
        s = {
            'sid': session.sid,
            'name': session.name,
            'membersCount': session.membersCount,
            'members': session.members,
        }
        sessionsList.append(s)
    return sessionsList

@router.get("/{supervisor}/{sessionsid}")
def get_session_sessionname(supervisor:str, sessionsid: str, auth: bool = Depends(RoleChecker("GS"))):
    sessions = lr.get(f'/users/{supervisor}', dict=False).lmnsessions
    for session in sessions:
        if sessionsid == session.sid:
            return {
                'sid': session.sid,
                'name': session.name,
                'membersCount': session.membersCount,
                'members': session.members,
            }
    raise HTTPException(status_code=404, detail=f"Session {sessionsid} not found by {supervisor}")

@router.delete("/{supervisor}/{sessionsid}")
def delete_session(sessionsid: str, auth: bool = Depends(RoleChecker("GS"))):
    cmd = f"sophomorix-session --session {sessionsid} --kill -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.post("/{supervisor}/{sessionname}")
def session_create(supervisor: str, sessionname: str, auth: bool = Depends(RoleChecker("GS"))):
    cmd = f"sophomorix-session --create --supervisor {supervisor} --comment {sessionname} -jj".split()
    return lmn_getSophomorixValue(cmd, '')