from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/query",
    tags=["Query"],
    responses={404: {"description": "Not found"}},
)

@router.get("/{school}/{keyword}", name="Search for an object in a specific school")
def query_user(school: str='default-school', keyword: str='', who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Get basic informations of a specific user.

    If **school** is *global*, search in all schools.
    If an user is found, the response provide some basic details like dn,
    sophomorixRole, cn, sophomorixSchoolName, samaccountname, etc ...

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param school: The school where to search, all schools if global is given
    :type school: basestring
    :param keyword: String to search for in the cn/displayName fields
    :type keyword: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of user's basic details (not complete, as dict)
    :rtype: list
    """


    if school == 'global':
        return lr.get(f'/search/{keyword}')

    return lr.get(f'/search/{keyword}', school=school)
