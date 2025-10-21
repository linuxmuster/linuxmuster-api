from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, UserListChecker, AuthenticatedUser
from utils.sophomorix import lmn_getSophomorixValue
from linuxmusterTools.samba_util.smbstatus import SMBConnections


router = APIRouter(
    prefix="/samba",
    tags=["Samba"],
    responses={404: {"description": "Not found"}},
)

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
def get_smbstatus(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Give the parsed output of smbstatus

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Dict containing usernames and objects
    :rtype: dict
    """


    connections = SMBConnections()

    return {
        user: details.asdict()
        for user,details in connections.users.items()
    }



