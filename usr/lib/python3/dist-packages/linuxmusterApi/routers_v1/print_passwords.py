import subprocess
from fastapi.responses import FileResponse
from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser, check_print_permissions
from utils.checks import get_schoolclass_or_404, get_project_or_404
from .body_schemas import PrintPasswordsSchoolclassesParameter, PrintPasswordsUsersParameter, PrintPasswordsProjectsParameter


router = APIRouter(
    prefix="/print-passwords",
    tags=["Print passwords"],
    responses={404: {"description": "Not found"}},
)

def sophomorixprint_cmd(who, config, schoolclasses=[], users=[]):
    """
    Run sophomorix-print with the given configuration and users.


    :param who: the caller
    :type who: AuthenticatedUser
    :param config: the print configuration (format, users, ...)
    :type config: PrintPasswords...Parameter
    :param schoolclasses: set of schoolclasses names
    :type schoolclasses: set
    :param users: set of user's cn
    :type users: set
    """


    cmd =  ['sophomorix-print', '--caller', who.user]

    if who.school == 'global' and config.school:
        cmd.extend(['--school', config.school])
    elif who.school != 'global':
        cmd.extend(['--school', who.school])

    if config.format == 'pdf':
        mtype = 'application/pdf'
    elif config.format == 'csv':
        # CSV
        mtype = 'text/csv'
    else:
        raise HTTPException(status_code=400, detail=f"{config.format} is a wrong format")

    if schoolclasses:
        cmd.extend(['--class', ','.join(config.schoolclasses)])
    elif users:
        cmd.extend(['--user', ','.join(users)])
    else:
        raise HTTPException(status_code=400, detail=f"This group does not contain users whose passwords can be printed out.")

    if config.pdflatex:
        cmd.extend(['--command', 'pdflatex'])

    if config.one_per_page:
        cmd.extend(['--one-per-page'])

    try:
        shell_env = {'TERM': 'xterm', 'SHELL': '/bin/bash',  'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',  'HOME': '/root', '_': '/usr/bin/python3'}
        subprocess.check_call(cmd, shell=False, env=shell_env)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/schoolclasses", name="Print passwords from schoolclasses")
def print_passwords_schoolclasses(config: PrintPasswordsSchoolclassesParameter, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Print passwords from multiple schoolclasses.

    The body parameters are:
        - format: pdf or csv (default pdf),
        - schoolclasses: list of valid schoolclasses,
        - one_per_page: boolean (print one password per page, default false),
        - pdflatex: booolean (use pdflatex or not, default false),
        - school: school of the user, may be necessary for globaladministrators.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    Unfortunately it's possible that the tex compilation failed, and in this case
    we don't get any error message from the backend.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schoolclasses details (dict)
    :rtype: list
    """

    if config.format == 'pdf':
        mtype = 'application/pdf'
    elif config.format == 'csv':
        # CSV
        mtype = 'text/csv'
    else:
        raise HTTPException(status_code=400, detail=f"{config.format} is a wrong format")

    for schoolclass in config.schoolclasses:
        get_schoolclass_or_404(schoolclass, who.school)

    sophomorixprint_cmd(who, config, schoolclasses=schoolclass)

    if len(config.schoolclasses) == 1:
        prefix = 'add'
        if config.schoolclasses[0]:
            prefix = config.schoolclasses[0]
    else:
        prefix = 'multiclass'

    filename = f'{prefix}-{who.user}.{config.format}'
    file_path = f'/var/lib/sophomorix/print-data/{filename}'

    return FileResponse(path=file_path, filename=filename, media_type=mtype)

@router.post("/projects", name="Print passwords from projects")
def print_passwords_projects(config: PrintPasswordsProjectsParameter, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Print passwords from the users multiple projects.

    Since it's not permitted to print admin passwords, and a teacher is not
    allowed to see passwords from other teachers, the resulting file will
    mostly only contain student's passwords.

    The body parameters are:
        - format: pdf or csv (default pdf),
        - projects: list of valid projects,
        - one_per_page: boolean (print one password per page, default false),
        - pdflatex: booolean (use pdflatex or not, default false),
        - school: school of the user, may be necessary for globaladministrators.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    Unfortunately it's possible that the tex compilation failed, and in this case
    we don't get any error message from the backend.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schoolclasses details (dict)
    :rtype: list
    """


    users_to_print = set()

    if config.format == 'pdf':
        mtype = 'application/pdf'
    elif config.format == 'csv':
        # CSV
        mtype = 'text/csv'
    else:
        raise HTTPException(status_code=400, detail=f"{config.format} is a wrong format")

    for project in config.projects:
        details = get_project_or_404(project, who.school)
        details.get_all_members()
        users_to_print = users_to_print.union(set(details.all_members))

    users_to_print = check_print_permissions(who, users_to_print)

    sophomorixprint_cmd(who, config, users=users_to_print)

    filename = f'user-{who.user}.{config.format}'
    file_path = f'/var/lib/sophomorix/print-data/{filename}'

    return FileResponse(path=file_path, filename=filename, media_type=mtype)


@router.post("/users", name="Print passwords of users")
def print_passwords_users(config: PrintPasswordsUsersParameter, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Print passwords of some users.

    Since it's not permitted to print admin passwords, and a teacher is not
    allowed to see passwords from other teachers, the resulting file will
    mostly only contain student's passwords.

    The body parameters are:
        - format: pdf or csv (default pdf),
        - users: list of valid user's cn,
        - one_per_page: boolean (print one password per page, default false),
        - pdflatex: booolean (use pdflatex or not, default false),
        - school: school of the user, may be necessary for globaladministrators.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    Unfortunately it's possible that the tex compilation failed, and in this case
    we don't get any error message from the backend.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all schoolclasses details (dict)
    :rtype: list
    """


    users_to_print = set(config.users)

    if config.format == 'pdf':
        mtype = 'application/pdf'
    elif config.format == 'csv':
        # CSV
        mtype = 'text/csv'
    else:
        raise HTTPException(status_code=400, detail=f"{config.format} is a wrong format")

    users_to_print = check_print_permissions(who, users_to_print)

    sophomorixprint_cmd(who, config, users=users_to_print)

    filename = f'user-{who.user}.{config.format}'
    file_path = f'/var/lib/sophomorix/print-data/{filename}'

    return FileResponse(path=file_path, filename=filename, media_type=mtype)


