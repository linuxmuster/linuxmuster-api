from dataclasses import asdict
from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.samba_util.smbstatus import SMBConnections
from linuxmusterTools.samba_util import DomainPasswordSettingsManager
from .body_schemas import DomainPasswordPolicy


router = APIRouter(
    prefix="/samba",
    tags=["Samba"],
    responses={404: {"description": "Not found"}},
)

@router.get("/passwordpolicy", name="Read the domain-wide Samba password policy")
def get_password_policy(who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Read the Samba AD domain-wide password policy.

    Equivalent to `samba-tool domain passwordsettings show`, read directly
    via SamDB. This is a single, domain-wide setting: it is not scoped per
    school, unlike /passwordconstraints.

    ### Access
    - school-administrators
    - global-administrators
    - teachers

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
    - teachers (only for themselves)

    \f
    :param username: login of the user
    :type username: str
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Dict containing usernames and objects
    :rtype: dict
    """

    if who.role == 'teacher':
        if username != who.user:
            raise HTTPException(status_code=403, detail=f"Forbidden")

    school = who.school
    if school == 'global':
        school = lr.getval(f'/users/{username}', 'sophomorixSchoolname')

    if school in (None, 'global'):
        # Unknown user, or global account without devices.csv
        room, connections = '', {}
    else:
        room, connections = SMBConnections(school=school).get_room_users(username)

    objects = {}
    for user, details in connections.items():
        ipv4, _, port = (details.ip4 or '').rpartition(':')
        objects[user] = {
            'COMPUTER': details.hostname,
            'IP': details.machine,
            'IPV4': ipv4,
            'PORT': port,
            'ROOM': details.room,
            'SMBSTATUS_LINE': details.rawline,
        }

    return {
        "usersList": list(objects.keys()),
        "name": room,
        "objects": objects,
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

    if who.role == "teacher":
        room, connections = smb_connections.get_room_users(who.user)
        if room:
            connections[who.user] = smb_connections.users[who.user]
    else:
        connections = smb_connections.users

    return {
        user: details.as_dict()
        for user,details in connections.items()
    }



