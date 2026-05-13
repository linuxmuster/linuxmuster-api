from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from utils.checks import get_extraclass_or_404
from utils.sophomorix import lmn_getSophomorixValue
from linuxmusterTools.print import print_schoolclass_list


router = APIRouter(
    prefix="/extraclasses",
    tags=["Extraclasses"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="List all extraclasses")
def get_all_extraclasses(who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List all extraclasses with all available informations.

    Output informations are e.g. cn, dn, members, etc...

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all extraclasses details (dict)
    :rtype: list
    """


    return lr.get('/extraclasses', school=who.school)

@router.get("/{schoolclass}", name="Get details of a specific extraclass")
def get_extraclass(schoolclass: str, all_members: bool = False, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List all available informations of a specific extraclass.

    Output informations are e.g. cn, dn, members, etc...
    The optional query parameter `all_members` is a boolean. If set to true, this endpoint will get all students
    informations.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param schoolclass: cn of the requested schoolclass
    :type schoolclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Extraclass details
    :rtype: dict
    """


    schoolclass = get_extraclass_or_404(schoolclass, who.school)

    if all_members:
        members_list = ",".join(schoolclass['sophomorixMembers'])
        schoolclass['members'] = lr.get(f'/batch_users/{members_list}') if members_list else []

    return schoolclass

