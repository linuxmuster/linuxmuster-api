from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/query",
    tags=["Query"],
    responses={404: {"description": "Not found"}},
)

@router.get("/{school}/{sam}")
def query_user(school: str='default-school', sam: str='', auth: bool = Depends(RoleChecker("GST"))):
    """
    Search user in LDAP per sAMAccountName.
    Accessible by global-administrators, school-administrators and teachers.

    :param school: school name
    :type school: basestring
    :param sam: samaccountname of the user. May be incomplete
    :type sam: basestring
    """

    if school == 'global':
        return lr.get(f'/search/{sam}')

    return lr.get(f'/search/{sam}', school=school)
