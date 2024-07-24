from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, UserListChecker, AuthenticatedUser
from utils.sophomorix import lmn_getSophomorixValue


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
    except IndexError as e:
        # response is an empty dict, not able to detect the room
        # or the other users in room
        return {
            "usersList": [],
            "name": '',
            "objects": {},
        }



