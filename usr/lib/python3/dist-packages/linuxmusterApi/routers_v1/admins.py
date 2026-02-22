from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, UserChecker, AuthenticatedUser, UserListChecker
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router_global = APIRouter(
    prefix="/globaladministrators",
    tags=["Global administrators"],
    responses={404: {"description": "Not found"}},
)

router_school = APIRouter(
    prefix="/schooladministrators",
    tags=["School administrators"],
    responses={404: {"description": "Not found"}},
)

@router_global.get("/", name="List all globaladministrators")
def get_all_globaladministrators(who: AuthenticatedUser = Depends(RoleChecker("G"))):
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


    return lr.get('/globaladministrators')

@router_global.get("/{admin}", name="User details")
def get_globaladministrator(admin: str, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Get all information of a specific globaladministrator.

    ### Access
    - global-administrators

    \f
    :param admin: The user to get the details from (samaccountname)
    :type admin: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """


    user_details = lr.get(f'/globaladministrators/{admin}')

    if user_details:
        return user_details

    raise HTTPException(status_code=404, detail=f"Globaladministrator {admin} not found")

@router_school.get("/", name="List all schooladministrators")
def get_all_schooladministrators(school: str = '', who: AuthenticatedUser = Depends(RoleChecker("G"))):
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
        return lr.get('/schooladministrators', school=school)

    return lr.get('/schooladministrators')

@router_school.get("/{admin}", name="User details")
def get_schooladministrator(admin: str, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Get all information of a specific schooladministrator.

    ### Access
    - global-administrators

    \f
    :param admin: The user to get the details from (samaccountname)
    :type admin: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All user's details
    :rtype: dict
    """


    user_details = lr.get(f'/schooladministrators/{admin}')

    if user_details:
        return user_details

    raise HTTPException(status_code=404, detail=f"Schooladministrator {admin} not found")

