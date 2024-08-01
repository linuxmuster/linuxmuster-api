from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from utils.checks import get_teacher_or_404


router = APIRouter(
    prefix="/teachers",
    tags=["Teachers"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name='List all teachers')
def get_all_teachers(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get all informations from all teachers.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all teachers details (dict)
    :rtype: list
    """


    return lr.get('/roles/teacher')

@router.get("/{teacher}", name="Get informations of a specific teacher")
def get_teacher(teacher: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get all informations of a specific teacher.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param teacher: samaccountname of the requested teacher
    :type teacher: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all teachers details (dict)
    :rtype: list
    """

    get_teacher_or_404(teacher, who.school)

    return lr.get(f'/users/{teacher}')

