from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/schools",
    tags=["Schools"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="List all schools")
def get_all_schools(who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## List all schools.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schools (dict)
    :rtype: list
    """


    return lr.get('/schools')

@router.get("/{school}", name="Retrieve informations from a specific school")
def get_all_schools(school: str, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Retrieve informations (projects, teachers, students, groups, etc ...)
    from a specific school. TODO ! NOT WORKING YET.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schools (dict)
    :rtype: list
    """

    school = lr.get(f'/schools/{school}')
    if not school:
        raise HTTPException(status_code=404, detail=f"School {school} not found")

    for item in ["schoolclasses", "projects"]:
        items = lr.getval(f'/{item}', 'cn')
        school[item] = {
            "number": len(items),
            "list": items
        }

    for role in ["student", "teacher", "globaladministrator", "schooladministrator", "parent", "staff"]:
        school[role] = len(lr.get(f'/rawroles/{role}'))

    return school