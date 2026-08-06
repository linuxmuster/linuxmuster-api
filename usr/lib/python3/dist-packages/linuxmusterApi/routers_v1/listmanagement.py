import os
import tempfile
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request

from security import RoleChecker, AuthenticatedUser
from utils.checks import check_valid_mgmtlist_or_404, check_tmp_dir
from linuxmusterTools.lmnfile import LMNFile
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from utils.sophomorix import process_user
from .body_schemas import MgmtList


router = APIRouter(
    prefix="/listmanagement",
    tags=["List Management"],
    responses={404: {"description": "Not found"}},
)

@router.get("/{school}/{mgmtlist}", name="Get the content of a specific management list")
def get_management_list_content(school: str, mgmtlist: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get the content of a management list (file like /etc/linuxmuster/sophomorix/default-school/teachers.csv).
    The school must be extra given, because it's not possible to know which school a global-administrator would like
    to request.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param school: A valid school where to get the content
    :type school: basestring
    :param mgmtlist: A valid role (plural) like 'teachers'
    :type mgmtlist: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Content of the csv file (list of dict, one dict per line in CSV)
    :rtype: list
    """


    path = check_valid_mgmtlist_or_404(mgmtlist, school)

    try:
        with LMNFile(path, 'r') as list:
            return list.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading {path}: {str(e)}")

@router.post("/{school}/{mgmtlist}", name="Write content of a specific management list")
def post_management_list_content(school: str, mgmtlist: str, content: MgmtList, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Write the content of a management list (file like /etc/linuxmuster/sophomorix/default-school/teachers.csv).
    The school must be extra given, because it's not possible to know which school a global-administrator would like
    to request. This will overwrite the content of the CSV file, but LMNFile automatically makes a backup of the old
    CSV file.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param school: A valid school where to post the content
    :type school: basestring
    :param mgmtlist: A valid role (plural) like 'teachers'
    :type mgmtlist: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :param content: Content of the CSV, see MgmtList attributes
    :type content: MgmtList
    :return: Content of the csv file (list of dict, one dict per line in CSV)
    :rtype: list
    """


    path = check_valid_mgmtlist_or_404(mgmtlist, school)

    try:
        with LMNFile(path, 'w') as list:
            return list.write(content.data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error writing {path}: {str(e)}")

@router.get("/sophomorix-check", name="Run sophomorix-check")
def do_sophomorix_check(background_tasks: BackgroundTasks, request: Request, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Run sophomorix-check as a background job.

    Returns a job id (pid) immediately; poll
    `GET /listmanagement/sophomorix-apply/status/{pid}` for the result (that
    endpoint isn't apply-specific despite its path, it just reads
    /tmp/lmnapi/{pid}.sophomorix.{log,status} for any job id). Configure
    `notifications.callback_url` in config.yml to be notified on completion
    instead of polling (see utils/notifications.py).

    ### Access
    - global-administrators
    - school-administrators

    ### This endpoint uses Sophomorix.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Job id (pid) to poll for the result
    :rtype: basestring
    """


    check_tmp_dir()

    _, logpath = tempfile.mkstemp(prefix=f'{who.school}.check.', suffix='.sophomorix.log', dir='/tmp/lmnapi')
    pid = logpath.replace(".sophomorix.log", "").replace("/tmp/lmnapi/", "")

    # -jj writes its JSON payload to stderr (see lmn_getSophomorixValue),
    # so both streams need to land in logpath, not just stdout.
    script = f'sophomorix-check -jj >> {logpath} 2>&1;'

    background_tasks.add_task(
        process_user, script, pid,
        command='sophomorix-check', school=who.school, caller=who.user,
        notifications_config=request.app.state.notifications,
    )

    return pid

@router.get("/sophomorix-apply", name="Run sophomorix-add, sophomorix-update, sophomorix-kill or all together.")
def do_sophomorix_apply(
        background_tasks: BackgroundTasks,
        request: Request,
        school: str,
        add: bool = False,
        update: bool = False,
        kill: bool = False,
        who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Run sophomorix-add, sophomorix-update, sophomorix-kill or all together.
    TODO: Actually in this form, the response could be a way too long. It would be better to launch a process and to
    follow this process with other requests.

    ### Access
    - global-administrators
    - school-administrators

    ### This endpoint uses Sophomorix.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :param school: A valid school where to apply the changes
    :type school: basestring
    :param add: Bool to launch sophomorix-add or not
    :param update: Bool to launch sophomorix-update or not
    :param kill: Bool to launch sophomorix-kill or not
    :return: Output of sophomorix-check
    :rtype: list of log lines
    """


    if school not in lr.getval('/schools', 'ou'):
        raise HTTPException(status_code=404, detail=f"{school} is not a valid school")

    if who.school != "global" and who.school != school:
        raise HTTPException(status_code=403, detail=f"Forbidden")

    check_tmp_dir()

    _, logpath = tempfile.mkstemp(prefix=f'{school}.', suffix='.sophomorix.log', dir='/tmp/lmnapi')

    script = ''
    commands_run = []

    if add:
        script += f'sophomorix-add --school {school} >> {logpath};'
        commands_run.append('sophomorix-add')

    if update:
        script += f'sophomorix-update --school {school} >> {logpath};'
        commands_run.append('sophomorix-update')

    if kill:
        script += f'sophomorix-kill --school {school} >> {logpath};'
        commands_run.append('sophomorix-kill')

    try:
        pid = logpath.replace(".sophomorix.log", "").replace("/tmp/lmnapi/", "")
        background_tasks.add_task(
            process_user, script, pid,
            command='+'.join(commands_run), school=school, caller=who.user,
            notifications_config=request.app.state.notifications,
        )

        return pid

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error applying changes with sophomorix: {str(e)}")

@router.get("/sophomorix-jobs/status/{pid}", name="Get log from an existing sophomorix process for management list.")
def get_status_sophomorix_apply(pid: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get last log of a sophomorix process for management list.

    ### Access
    - global-administrators
    - school-administrators

    ### This endpoint uses Sophomorix.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :param pid: PID of the runnning process like SCHOOL.RAND. The log path is /tmp/PID.sophomorix.log
    :type pid: basestring
    :return: Output of sophomorix commands
    :rtype: list of log lines
    """


    logpath = f"/tmp/lmnapi/{pid}.sophomorix.log"
    statuspath = f"/tmp/lmnapi/{pid}.sophomorix.status"

    if not os.path.isfile(logpath) or not os.path.isfile(statuspath):
        raise HTTPException(status_code=404, detail=f"Log file {logpath} not found.")

    try:
        with open(logpath, 'r') as f:
            log = f.readlines()

        with open(statuspath, 'r') as f:
            status = f.read()

        return {"status": status, "log": log}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading log file {logpath}: {str(e)}")