from fastapi import APIRouter, Depends, HTTPException, Response, status
from datetime import datetime

from security import UserChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNLdapWriter as lw
from linuxmusterTools.common import Validator, STRING_RULES


router = APIRouter(
    prefix="/sessions",
    tags=["Sessions"],
    responses={404: {"description": "Not found"}},
)

@router.get("/{user}")
def session_user(user: str, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    sessions = lr.get(f'/users/{user}', school=who.school, dict=False).lmnsessions
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

@router.get("/{user}/{sessionsid}")
def get_session_sessionname(user:str, sessionsid: str, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    sessions = lr.get(f'/users/{user}', school=who.school, dict=False).lmnsessions
    for session in sessions:
        if sessionsid == session.sid:
            return {
                'sid': session.sid,
                'name': session.name,
                'membersCount': session.membersCount,
                'members': session.members,
            }
    raise HTTPException(status_code=404, detail=f"Session {sessionsid} not found by {user}")

@router.delete("/{user}/{sessionsid}", status_code=204)
def delete_session(user:str, sessionsid: str, response: Response, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    sessions = lr.get(f'/users/{user}', school=who.school, dict=False).lmnsessions
    modified = False
    for index, session in enumerate(sessions):
        if sessionsid == session.sid:
            sessions.pop(index)
            modified = True
            break

    if modified:
        ldap_sessions = [f"{session.sid};{session.name};{','.join(session.members)};" for session in sessions]
        lw.set(user, 'user', {'sophomorixSessions': ldap_sessions})
    else:
        response.status_code = status.HTTP_304_NOT_MODIFIED

    return

@router.post("/{user}/{sessionname}")
def session_create(user: str, sessionname: str, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    if not Validator.check_session(sessionname):
        raise HTTPException(status_code=422, detail=f"{sessionname} is not a valid name. Valid chars are {STRING_RULES['session']}")

    sid = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    new_session = f"{sid};{sessionname};;"
    lw.set(user, 'user', {'sophomorixSessions': new_session}, add=True)
    return

