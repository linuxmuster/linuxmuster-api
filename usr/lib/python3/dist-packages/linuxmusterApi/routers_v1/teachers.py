from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/teachers",
    tags=["Teachers"],
    responses={404: {"description": "Not found"}},
)


def check_teacher(teacher):
    teachers = [s['cn'] for s in lr.get('/roles/teacher', attributes=['cn'])]
    if teacher not in teachers:
        raise HTTPException(status_code=404, detail=f"Teacher {teacher} not found")

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

    check_teacher(teacher)

    return lr.get(f'/users/{teacher}')

