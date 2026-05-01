from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.print import print_schoolclass_list
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.ldapconnector import LMNSchoolclass
from utils.checks import get_schoolclass_or_404
from utils.sophomorix import lmn_getSophomorixValue
from .body_schemas import SchoolclassAttr


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


    if who.role in ["schooladministrator", "globaladministrator"]:
        return lr.get('/schoolclasses', school=who.school)
    else:
        schoolclasses = []
        for schoolclass in lr.get('/schoolclasses', school=who.school):
            if not schoolclass['sophomorixHidden'] or who.dn in schoolclass['member']:
                schoolclasses.append(schoolclass)

        return schoolclasses

@router.get("/{schoolclass}", name="Get details of a specific schoolclass")
def get_schoolclass(schoolclass: str, all_members: bool = False, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List all available informations of a specific schoolclass.

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
    :return: Schoolclasses details
    :rtype: dict
    """


    schoolclass = get_schoolclass_or_404(schoolclass, who)

    if all_members:
        schoolclass['members'] = [lr.get(f'/users/{member}') for member in schoolclass['sophomorixMembers']]

    return schoolclass

@router.patch("/{schoolclass}", name="Update some parameters of a specific schoolclass")
def modify_schoolclass(schoolclass: str, schoolclass_details: SchoolclassAttr, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Update some parameters of a specific schoolclass

    *schoolclass_details* are the attribute of the group, like *description*,
    *join* if the schoolclass should be joinable, *hide*, etc ... and can be partial.

    ### Access
    - global-administrators
    - school-administrators

    ### This endpoint uses Sophomorix.

    \f
    :param schoolclass: cn of the schoolclass to update
    :type schoolclass: basestring
    :param schoolclass_details: Parameter of the group, see NewGroup attributes
    :type schoolclass_details: NewGroup
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Result of the sophomorix command
    :rtype: list
    """


    # School specific request. For global-admins, it will search in all schoolclasses from all schools
    schoolclass_data = lr.get(f'/schoolclasses/{schoolclass}', school=who.school)

    if not schoolclass_data:
       raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found.")

    options = []

    if schoolclass_details.description:
        options.extend(['--description', schoolclass_details.description])

    if schoolclass_details.join:
        options.append('--join')
    else:
        options.append('--nojoin')

    if schoolclass_details.hide:
        options.append('--hide')
    else:
        options.append('--nohide')

    if schoolclass_details.mailalias:
        options.append('--mailalias')
    else:
        options.append('--nomailalias')

    if schoolclass_details.maillist:
        options.append('--maillist')
    else:
        options.append('--nomaillist')

    if schoolclass_details.mailquota is not None:
        # Only mailquota without comment
        options.extend(['--mailquota', f"{schoolclass_details.mailquota}:"])

    cmd = ['sophomorix-class',  *options, '-c', schoolclass.lower(), '-jj']

    try:
        result =  lmn_getSophomorixValue(cmd, '')
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))

    output = result.get("OUTPUT", [{}])[0]
    if output.get("TYPE", "") == "ERROR":
        raise HTTPException(status_code=400, detail=output["MESSAGE_EN"])

    if schoolclass_details.displayName:
        if "-" in schoolclass:
            school = schoolclass.lower().split("-")[0]
        else:
            school = 'default-school'
        SchoolclassWriter = LMNSchoolclass(f"{schoolclass.lower()}", school=school)
        SchoolclassWriter.setattr(data={'displayName': schoolclass_details.displayName})

    return result

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


    schoolclass_data = get_schoolclass_or_404(schoolclass, who, as_dict=False)

    return schoolclass_data.get_first_passwords()

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


    get_schoolclass_or_404(schoolclass, who)

    return lr.get(f'/schoolclasses/{schoolclass}/students')

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


    schoolclass_data = get_schoolclass_or_404(schoolclass, who)

    if who.dn in schoolclass_data['member']:
        return f"Already member of {schoolclass}"

    if who.role == "teacher":
        if not schoolclass_data['sophomorixJoinable']:
            raise HTTPException(status_code=403, detail=f"Schoolclass {schoolclass} is not joinable.")

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


    schoolclass_data = get_schoolclass_or_404(schoolclass, who)

    if who.dn not in schoolclass_data['member']:
        return f"Already not a member of {schoolclass}"

    if not schoolclass_data['sophomorixJoinable']:
        raise HTTPException(status_code=403, detail=f"Schoolclass {schoolclass} is not joinable, and cannot be quitted.")

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


    schoolclass = get_schoolclass_or_404(schoolclass, who, as_dict=False)

    file_path = schoolclass.students_csv()
    filename = file_path.split('/')[-1]

    return FileResponse(path=file_path, filename=filename, media_type='csv')

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


    schoolclass = get_schoolclass_or_404(schoolclass, who, as_dict=False)

    try:
        file_path = print_schoolclass_list(schoolclass.cn, who.user, school=who.school)
        filename = file_path.split('/')[-1]
    except Exception as e:
        # Temporary 500, must be better filtered
        raise HTTPException(status_code=500, detail=f"Failed to generate list: {str(e)}")

    return FileResponse(path=file_path, filename=filename, media_type='pdf')

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


    get_schoolclass_or_404(schoolclass, who)

    members = lr.getval(f'/units/{schoolclass}-parents', 'member')
    response = []

    if members is not None:
        for member_dn in members:
            response.append(lr.get(f'/dn/{member_dn}'))

    return response

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


    get_schoolclass_or_404(schoolclass, who)

    members = lr.getval(f'/units/{schoolclass}-teachers', 'member')
    response = []

    if members is not None:
        for member_dn in members:
            response.append(lr.get(f'/dn/{member_dn}'))

    return response
