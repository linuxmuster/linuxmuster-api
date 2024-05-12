from fastapi import APIRouter, Depends, HTTPException, Response, status
from datetime import datetime
from pydantic import BaseModel

from security import UserChecker, UserListChecker, AuthenticatedUser
from checks import get_user_or_404
from linuxmusterTools.ldapconnector import LMNLdapWriter as lw
from linuxmusterTools.common import Validator, STRING_RULES


router = APIRouter(
    prefix="/sessions",
    tags=["Sessions"],
    responses={404: {"description": "Not found"}},
)

class UserList(BaseModel):
    users: list | None = None

@router.get("/{user}")
def session_user(user: str, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    user_details = get_user_or_404(user, who.school)
    sessions = user_details.lmnsessions
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
    user_details = get_user_or_404(user, who.school)
    sessions = user_details.lmnsessions
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
def delete_session(user:str, sessionsid: str, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    user_details = get_user_or_404(user, who.school)
    sessions = user_details.lmnsessions
    for index, session in enumerate(sessions):
        if sessionsid == session.sid:
            old_session = f"{session.sid};{session.name};{','.join(session.members)};"
            lw.delete(user, 'user', {'sophomorixSessions': old_session})
            return
    else:
       raise HTTPException(status_code=404, detail=f"Session {sessionsid} not found by {user}")

@router.post("/{user}/{sessionname}")
def session_create(user: str, sessionname: str, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    if not Validator.check_session_name(sessionname):
        raise HTTPException(status_code=422, detail=f"{sessionname} is not a valid name. Valid chars are {STRING_RULES['session']}")

    sid = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    new_session = f"{sid};{sessionname};;"
    try:
        lw.set(user, 'user', {'sophomorixSessions': new_session}, add=True)
    except Exception as e:
       raise HTTPException(status_code=404, detail=str(e))
    return

@router.delete("/{user}/{sessionsid}/members", status_code=204)
def remove_user_from_session(user:str, sessionsid: str, userlist: UserList, who: AuthenticatedUser = Depends(UserListChecker("GST"))):

    if not userlist.users:
        # Nothing to do
        return

    user_details = get_user_or_404(user, who.school)
    sessions = user_details.lmnsessions

    for index, session in enumerate(sessions):
        if sessionsid == session.sid:
            old_session = f"{session.sid};{session.name};{','.join(session.members)};"
            lw.delete(user, 'user', {'sophomorixSessions': old_session})

            to_delete = set(userlist.users)
            members_set = set(session.members)
            members_set.difference_update(to_delete)
            session.members = list(members_set)

            new_session = f"{session.sid};{session.name};{','.join(session.members)};"
            lw.set(user, 'user', {'sophomorixSessions': new_session}, add=True)

            return
    else:
       raise HTTPException(status_code=404, detail=f"Session {sessionsid} not found by {user}")

@router.post("/{user}/{sessionsid}/members")
def add_user_to_session(user: str, sessionsid: str, userlist: UserList, who: AuthenticatedUser = Depends(UserListChecker("GST"))):

    if not userlist.users:
        # Nothing to do
        return

    user_details = get_user_or_404(user, who.school)
    sessions = user_details.lmnsessions

    for index, session in enumerate(sessions):
        if sessionsid == session.sid:
            old_session = f"{session.sid};{session.name};{','.join(session.members)};"
            lw.delete(user, 'user', {'sophomorixSessions': old_session})

            session.members += userlist.users
            session.members = list(set(session.members))

            new_session = f"{session.sid};{session.name};{','.join(session.members)};"
            lw.set(user, 'user', {'sophomorixSessions': new_session}, add=True)

            return
    else:
       raise HTTPException(status_code=404, detail=f"Session {sessionsid} not found by {user}")