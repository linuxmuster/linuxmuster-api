from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from utils.checks import get_schoolclass_or_404
from utils.sophomorix import lmn_getSophomorixValue
from linuxmusterTools.print import print_schoolclass_list


router = APIRouter(
    prefix="/schoolclasses",
    tags=["Schoolclasses"],
    responses={404: {"description": "Not found"}},
)

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


    return lr.get('/schoolclasses', school=who.school)

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


    schoolclass = get_schoolclass_or_404(schoolclass, who.school)

    if who.role in ["schooladministrator", "globaladministrator"] or who.user in schoolclass['sophomorixAdmins']:
        schoolclass['members'] = [lr.get(f'/users/{member}') for member in schoolclass['sophomorixMembers']]
        return schoolclass

    return HTTPException(status_code=401, detail=f"Teacher {who.user} is not member of schoolclass {schoolclass['cn']}")

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


    schoolclass_data = get_schoolclass_or_404(schoolclass, who.school)

    if who.role in ["schooladministrator", "globaladministrator"] or who.user in schoolclass_data['sophomorixAdmins']:
        return lr.get(f'/schoolclasses/{schoolclass}', dict=False).get_first_passwords()

    return HTTPException(status_code=401, detail=f"Teacher {who.user} is not member of schoolclass {schoolclass_data['cn']}")

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


    schoolclass_data = get_schoolclass_or_404(schoolclass, who.school)

    if who.role in ["schooladministrator", "globaladministrator"] or who.user in schoolclass_data['sophomorixAdmins']:
        return lr.get(f'/schoolclasses/{schoolclass}/students')

    return HTTPException(status_code=401, detail=f"Teacher {who.user} is not member of schoolclass {schoolclass_data['cn']}")

@router.post("/{schoolclass}/join", name="Join an existing schoolclass")
def join_schoolclass(schoolclass: str, who: AuthenticatedUser = Depends(RoleChecker("T"))):
    """
    ## Join an existing schoolclass

    This endpoint let the authenticated user join an existing schoolclass, where *schoolclass* is the cn of this
    schoolclass.

    ### Access
    - teachers

    ### This endpoint uses Sophomorix.

    \f
    :param schoolclass: cn of the schoolclass to join
    :type schooclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """

    get_schoolclass_or_404(schoolclass, who.school)

    cmd = ['sophomorix-class',  '--addadmins', who.user, '-c', schoolclass.lower(), '-jj']
    result =  lmn_getSophomorixValue(cmd, '')

    output = result.get("OUTPUT", [{}])[0]
    if output.get("TYPE", "") == "ERROR":
        raise HTTPException(status_code=400, detail=output["MESSAGE_EN"])

    return result

@router.post("/{schoolclass}/quit", name="Quit an existing schoolclass")
def quit_schoolclass(schoolclass: str, who: AuthenticatedUser = Depends(RoleChecker("T"))):
    """
    ## Quit an existing schoolclass

    This endpoint let the authenticated user quit an existing schoolclass, where *schoolclass* is the cn of this
    schoolclass.

    ### Access
    - teachers

    ### This endpoint uses Sophomorix.

    \f
    :param schoolclass: cn of the schoolclass to quit
    :type schooclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    get_schoolclass_or_404(schoolclass, who.school)

    cmd = ['sophomorix-class',  '--removeadmins', who.user, '-c', schoolclass.lower(), '-jj']
    result =  lmn_getSophomorixValue(cmd, '')

    output = result.get("OUTPUT", [{}])[0]
    if output.get("TYPE", "") == "ERROR":
        raise HTTPException(status_code=400, detail=output["MESSAGE_EN"])

    return result

@router.get("/{schoolclass}/csv_students_list", name="Generate a students csv list from a specific schoolclass")
def schoolclass_students_csv(schoolclass: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Generate a students csv list from a specific schoolclass

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param schoolclass: cn of the schoolclass
    :type schooclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: CSV list of all students in the schoolclass
    :rtype: csv
    """


    schoolclass = lr.get(f'/schoolclasses/{schoolclass}', school=who.school, dict=False)

    if not schoolclass:
        raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found")

    if who.role in ["schooladministrator", "globaladministrator"] or who.user in schoolclass.sophomorixAdmins:
        file_path = schoolclass.students_csv()
        filename = file_path.split('/')[-1]

        return FileResponse(path=file_path, filename=filename, media_type='csv')

    return HTTPException(status_code=401, detail=f"Teacher {who.user} is not member of schoolclass {schoolclass.cn}")

@router.get("/{schoolclass}/pdf_students_list", name="Generate a students list as PDF from a specific schoolclass")
def schoolclass_students_pdf(schoolclass: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Generate a students list as PDF from a specific schoolclass

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param schoolclass: cn of the schoolclass
    :type schooclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: CSV list of all students in the schoolclass
    :rtype: csv
    """


    schoolclass = lr.get(f'/schoolclasses/{schoolclass}', school=who.school, dict=False)

    if not schoolclass:
        raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found")

    if who.role in ["schooladministrator", "globaladministrator"] or who.user in schoolclass.sophomorixAdmins:
        try:
            file_path = print_schoolclass_list(schoolclass.cn, who.user, school=who.school)
            filename = file_path.split('/')[-1]
        except Exception as e:
            # Temporary 500, must be better filtered
            raise HTTPException(status_code=500, detail=f"Failed to generate list: {str(e)}")

        return FileResponse(path=file_path, filename=filename, media_type='pdf')

    return HTTPException(status_code=401, detail=f"Teacher {who.user} is not member of schoolclass {schoolclass.cn}")

@router.get("/{schoolclass}/parents", name="Get the list of parents from a specific schoolclass")
def schoolclass_parents(schoolclass: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List the parents from a specific schoolclass

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param schoolclass: cn of the schoolclass
    :type schooclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all parents in the schoolclass
    :rtype: list
    """


    schoolclass_data = get_schoolclass_or_404(schoolclass, who.school)

    if who.role in ["schooladministrator", "globaladministrator"] or who.user in schoolclass_data['sophomorixAdmins']:
        members = lr.getval(f'/units/{schoolclass}-parents', 'member')
        response = []

        if members is not None:
            for member_dn in members:
                response.append(lr.get(f'/dn/{member_dn}'))

        return response

    return HTTPException(status_code=401, detail=f"Teacher {who.user} is not member of schoolclass {schoolclass_data['cn']}")

@router.get("/{schoolclass}/teachers", name="Get the list of teachers from a specific schoolclass")
def schoolclass_teachers(schoolclass: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List the teachers from a specific schoolclass

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param schoolclass: cn of the schoolclass
    :type schooclass: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all teachers in the schoolclass
    :rtype: list
    """


    get_schoolclass_or_404(schoolclass, who.school)

    members = lr.getval(f'/units/{schoolclass}-teachers', 'member')
    response = []

    if members is not None:
        for member_dn in members:
            response.append(lr.get(f'/dn/{member_dn}'))

    return response
