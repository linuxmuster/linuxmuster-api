from fastapi import APIRouter, Depends, HTTPException, Response, status
from datetime import datetime

from security import UserChecker, UserListChecker, AuthenticatedUser
from utils.checks import get_user_or_404
from .body_schemas import UserList
from linuxmusterTools.ldapconnector import LMNLdapWriter as lw
from linuxmusterTools.common import Validator, STRING_RULES


router = APIRouter(
    prefix="/sessions",
    tags=["Sessions"],
    responses={404: {"description": "Not found"}},
)


@router.get("/{user}", name="Get all sessions of a specific user")
def session_user(user: str, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Get all sessions details of a specific user and return a list of sessions.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data)

    \f
    :param user: Valid LDAP samaccountname
    :type user: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of sessions details (details as dict)
    :rtype: list
    """


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

@router.get("/{user}/{sessionsid}", name="Get all details from a specific session sid of a specific user")
def get_session_sessionname(user:str, sessionsid: str, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Get all details from a specific session of a specific user.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data)

    \f
    :param user: Valid LDAP samaccountname
    :type user: basestring
    :param sessionsid: Valid sessionsid
    :type sessionsid: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Session details
    :rtype: dict
    """


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

@router.delete("/{user}/{sessionsid}", status_code=204, name="Delete a specific session from a specific user")
def delete_session(user:str, sessionsid: str, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Delete a specific session of a specific user.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data)

    \f
    :param user: Valid LDAP samaccountname
    :type user: basestring
    :param sessionsid: Valid sessionsid
    :type sessionsid: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    user_details = get_user_or_404(user, who.school)
    sessions = user_details.lmnsessions
    for index, session in enumerate(sessions):
        if sessionsid == session.sid:
            old_session = f"{session.sid};{session.name};{','.join(session.members)};"
            lw.delete(user, 'user', {'sophomorixSessions': old_session})
            return
    else:
       raise HTTPException(status_code=404, detail=f"Session {sessionsid} not found by {user}")

@router.post("/{user}/{sessionname}", name="Create a new session for a specific user")
def session_create(user: str, sessionname: str, userlist: UserList | None = None, who: AuthenticatedUser = Depends(UserChecker("GST"))):
    """
    ## Create a new session for a specific user.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data)

    ### TODO
    - provide a way to direcly add members.

    \f
    :param user: Valid LDAP samaccountname
    :type user: basestring
    :param sessionname: Valid sessionname, will be checked
    :type sessionname: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if not Validator.check_session_name(sessionname):
        raise HTTPException(status_code=422, detail=f"{sessionname} is not a valid name. Valid chars are {STRING_RULES['session']}")

    sid = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    members = ""
    if userlist:
        if userlist.users:
            members = ",".join(set(userlist.users))

    new_session = f"{sid};{sessionname};{members};"

    try:
        lw.set(user, 'user', {'sophomorixSessions': new_session}, add=True)
        return
    except Exception as e:
       raise HTTPException(status_code=404, detail=str(e))

@router.delete("/{user}/{sessionsid}/members", status_code=204, name="Remove members from a specific session of a specific user")
def remove_user_from_session(user:str, sessionsid: str, userlist: UserList, who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    ## Remove members from a specific session of a specific user.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data)

    \f
    :param user: Valid LDAP samaccountname
    :type user: basestring
    :param sessionsid: Valid sessionsid
    :type sessionsid: basestring
    :param userlist: List of samaccountname to delete
    :type userlist: UserList
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if not userlist.users:
        # Nothing to do
        raise HTTPException(status_code=400, detail=f"Missing userlist of members to delete")

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

@router.post("/{user}/{sessionsid}/members", name="Add members to a specific session of a specific user")
def add_user_to_session(user: str, sessionsid: str, userlist: UserList, who: AuthenticatedUser = Depends(UserListChecker("GST"))):
    """
    ## Add members to a specific session of a specific user.

    ### Access
    - global-administrators
    - school-administrators
    - teachers (own data)

    \f
    :param user: Valid LDAP samaccountname
    :type user: basestring
    :param sessionsid: Valid sessionsid
    :type sessionsid: basestring
    :param userlist: List of samaccountname to add
    :type userlist: UserList
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if not userlist.users:
        # Nothing to do
        raise HTTPException(status_code=400, detail=f"Missing userlist of members to add")

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