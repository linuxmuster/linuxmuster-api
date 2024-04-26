from fastapi import APIRouter, Depends, HTTPException, Response, status
from datetime import datetime

from security import RoleChecker
from utils import lmn_getSophomorixValue
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNLdapWriter as lw
from linuxmusterTools.common import Validator, STRING_RULES


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

@router.delete("/{supervisor}/{sessionsid}", status_code=204)
def delete_session(supervisor:str, sessionsid: str, response: Response, auth: bool = Depends(RoleChecker("GS"))):
    sessions = lr.get(f'/users/{supervisor}', dict=False).lmnsessions
    modified = False
    for index, session in enumerate(sessions):
        if sessionsid == session.sid:
            sessions.pop(index)
            modified = True
            break

    if modified:
        ldap_sessions = [f"{session.sid};{session.name};{','.join(session.members)};" for session in sessions]
        lw.set(supervisor, 'user', {'sophomorixSessions': ldap_sessions})
    else:
        response.status_code = status.HTTP_304_NOT_MODIFIED

    return

@router.post("/{supervisor}/{sessionname}")
def session_create(supervisor: str, sessionname: str, auth: bool = Depends(RoleChecker("GS"))):
    if not Validator.check_session(sessionname):
        raise HTTPException(status_code=422, detail=f"{sessionname} is not a valid name. Valid chars are {STRING_RULES['session']}")

    sid = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    new_session = f"{sid};{sessionname};;"
    lw.set(supervisor, 'user', {'sophomorixSessions': new_session}, add=True)
    return

