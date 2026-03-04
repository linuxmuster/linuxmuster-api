import os
import tempfile
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks

from security import RoleChecker, AuthenticatedUser
from utils.checks import check_valid_mgmtlist_or_404, check_tmp_dir
from linuxmusterTools.lmnfile import LMNFile
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from utils.sophomorix import lmn_getSophomorixValue, process_user
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
def do_sophomorix_check(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Run sophomorix-check.

    ### Access
    - global-administrators
    - school-administrators

    ### This endpoint uses Sophomorix.

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Output of sophomorix-check
    :rtype: dict
    """


    sophomorixCommand = ['sophomorix-check', '-jj']
    results = lmn_getSophomorixValue(sophomorixCommand, '')
    ## Remove UPDATE entries which are also in KILL ( necessary to show it in KILL and UPDATE ? )

    if "CHECK_RESULT" in results:
        if "UPDATE" in results["CHECK_RESULT"] and "KILL" in results["CHECK_RESULT"]:
            for user_update in tuple(results["CHECK_RESULT"]["UPDATE"]):
                if user_update in results["CHECK_RESULT"]["KILL"]:
                    del results["CHECK_RESULT"]["UPDATE"][user_update]
    return results

@router.get("/sophomorix-apply", name="Run sophomorix-add, sophomorix-update, sophomorix-kill or all together.")
async def do_sophomorix_apply(
        background_tasks: BackgroundTasks,
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

    if add:
        script += f'sophomorix-add --school {school} >> {logpath};'

    if update:
        script += f'sophomorix-update --school {school} >> {logpath};'

    if kill:
        script += f'sophomorix-kill --school {school} >> {logpath};'

    try:
        pid = logpath.replace(".sophomorix.log", "").replace("/tmp/lmnapi/", "")
        background_tasks.add_task(process_user, script, pid)

        return pid

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error applying changes with sophomorix: {str(e)}")

@router.get("/sophomorix-apply/status/{pid}", name="Get log from an existing sophomorix process for management list.")
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