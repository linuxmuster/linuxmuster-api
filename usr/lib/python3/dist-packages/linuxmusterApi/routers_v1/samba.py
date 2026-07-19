from dataclasses import asdict
from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from utils.sophomorix import lmn_getSophomorixValue
from linuxmusterTools.samba_util.smbstatus import SMBConnections
from linuxmusterTools.samba_util import DomainPasswordSettingsManager
from .body_schemas import DomainPasswordPolicy


router = APIRouter(
    prefix="/samba",
    tags=["Samba"],
    responses={404: {"description": "Not found"}},
)

@router.get("/passwordpolicy", name="Read the domain-wide Samba password policy")
def get_password_policy(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Read the Samba AD domain-wide password policy.

    Equivalent to `samba-tool domain passwordsettings show`, read directly
    via SamDB. This is a single, domain-wide setting: it is not scoped per
    school, unlike /passwordconstraints.

    ### Access
    - school-administrators
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: min_pwd_length, min_pwd_age, max_pwd_age, complexity
    :rtype: dict
    """


    return asdict(DomainPasswordSettingsManager().get())

@router.post("/passwordpolicy", name="Modify the domain-wide Samba password policy")
def post_password_policy(content: DomainPasswordPolicy, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Modify the Samba AD domain-wide password policy.

    Equivalent to `samba-tool domain passwordsettings set`, applied directly
    via SamDB. Only the given fields are changed. This affects every school
    at once (there is no per-school Samba domain), so it is restricted to
    global-administrators.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the write, read from API Token
    :type who: AuthenticatedUser
    :param content: Fields to change, see DomainPasswordPolicy
    :type content: DomainPasswordPolicy
    :return: The policy after the change
    :rtype: dict
    """


    try:
        DomainPasswordSettingsManager().set(**content.model_dump(exclude_none=True))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return asdict(DomainPasswordSettingsManager().get())

@router.get("/userInRoom/{username}", name="List users connected in the same room.")
def get_groups_list(username: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Search for users connected in the same room as the given username.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Dict containing usernames and objects
    :rtype: dict
    """

    school = who.school

    if who.role == 'teacher':
        if username != who.user:
            raise HTTPException(status_code=403, detail=f"Forbidden")

    try:
        sophomorixCommand = [
            'sophomorix-query', '-jj', '--smbstatus',
            '--schoolbase', school,
            '--query-user', username
        ]

        response = lmn_getSophomorixValue(sophomorixCommand, '')
        # remove our own
        room = response[username]['ROOM']
        response.pop(username, None)
        return {
            "usersList": list(response.keys()) if response else [],
            "name": room,
            "objects": response,
        }
    except (IndexError, Exception) as e:
        # response is an empty dict, not able to detect the room
        # or the other users in room
        return {
            "usersList": [],
            "name": '',
            "objects": {},
        }

@router.get("/smbstatus", name="Parsed output of smbstatus")
def get_smbstatus(who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Give the parsed output of smbstatus.
    Asking as a teacher only retrieve the informations of the same room.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Dict containing usernames and objects
    :rtype: dict
    """


    smb_connections = SMBConnections()

    connections = {
        user: details.as_dict()
        for user,details in smb_connections.users.items()
    }

    if who.role == "teacher":
        if who.user not in connections:
            # Teacher not found in samba connections
            return {}
        else:
            user_room = connections[who.user].room
            return {
                user: details
                for user,details in connections.items()
                if details.room == user_room
            }
    else:
        return {
            user: details.as_dict()
            for user,details in connections.users.items()
        }



