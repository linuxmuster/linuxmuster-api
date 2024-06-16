from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/schoolclasses",
    tags=["Schoolclasses"],
    responses={404: {"description": "Not found"}},
)

def check_schoolclass(schoolclass):
    schoolclasses = [s['cn'] for s in lr.get('/schoolclasses', attributes=['cn'])]
    if schoolclass not in schoolclasses:
        raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found")

@router.get("/", name="List all schoolclasses")
def get_all_schoolclasses(who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List all schoolclasses with all available informations.

    Output informations are e.g. cn, dn, members, etc...

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schoolclasses details (dict)
    :rtype: list
    """


    return lr.get('/schoolclasses')

@router.get("/{schoolclass}", name="Get details of a specific schoolclass")
def get_schoolclass(schoolclass: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List all available informations of a specific schooclass.

    Output informations are e.g. cn, dn, members, etc...

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param schoolclass: cn of the requested schoolclass
    :type schoolclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schoolclasses details (dict)
    :rtype: list
    """


    # TODO: Check group membership
    check_schoolclass(schoolclass)

    return lr.get(f'/schoolclasses/{schoolclass}')

@router.get("/{schoolclass}/first_passwords", name="Get all first passwords of the members of a specific schoolclass")
def get_schoolclass_passwords(schoolclass: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Get the first passwords of all members of a specific schooclass.

    The **first password**, also known as default password, is the readable password
    in the LDAP account, and the one to which it's possible to retrograde if the
    user looses its **current password**.
    The boolean *firstPasswordStillSet* indicates if the first password is still
    used as current password.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param schoolclass: cn of the requested schoolclass
    :type schoolclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all members and passwords details as dict (value, and boolean
    to indicate if still set as current password
    :rtype: list
    """


    # TODO: Check group membership
    check_schoolclass(schoolclass)

    return lr.get(f'/schoolclasses/{schoolclass}', dict=False).get_first_passwords()

@router.get("/{schoolclass}/students", name="Details of students of a specific schoolclass")
def get_schoolclass_passwords(schoolclass: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Get all details of all members of a specific schooclass.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param schoolclass: cn of the requested schoolclass
    :type schoolclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all members details (dict)
    :rtype: list
    """


    # TODO: Check group membership
    check_schoolclass(schoolclass)

    return lr.get(f'/schoolclasses/{schoolclass}/students')