from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router_global = APIRouter(
    prefix="/globalbindusers",
    tags=["Global bindusers"],
    responses={404: {"description": "Not found"}},
)

router_school = APIRouter(
    prefix="/schoolbindusers",
    tags=["School bindusers"],
    responses={404: {"description": "Not found"}},
)

@router_global.get("/", name="List all global bindusers")
def get_all_globalbindusers(who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Get basic information from all users.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all users details (dict)
    :rtype: list
    """


    return lr.get('/globalbindusers')

@router_global.get("/{binduser}", name="User details")
def get_globaladministrator(binduser: str, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Get all information of a specific globaladministrator.

    ### Access
    - global-administrators

    \f
    :param binduser: The user to get the details from (samaccountname)
    :type binduser: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """


    user_details = lr.get(f'/globalbindusers/{binduser}')

    if user_details:
        return user_details

    raise HTTPException(status_code=404, detail=f"Globalbinduser {binduser} not found")

@router_school.get("/", name="List all school bindusers")
def get_all_schoolbindusers(school: str = '', who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get basic information from all users.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all users details (dict)
    :rtype: list
    """


    if school:
        # Filter per school
        return lr.get('/schoolbindusers', school=school)

    return lr.get('/schoolbindusers')

@router_school.get("/{binduser}", name="User details")
def get_schoolbinduser(binduser: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get all information of a specific school binduser.

    ### Access
    - global-administrators

    \f
    :param binduser: The user to get the details from (samaccountname)
    :type binduser: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """


    user_details = lr.get(f'/schoolbindusers/{binduser}')

    if user_details:
        return user_details

    raise HTTPException(status_code=404, detail=f"Schoolbinduser {binduser} not found")

