import subprocess
from fastapi.responses import FileResponse
from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser
from utils.checks import get_schoolclass_or_404
from .body_schemas import PrintPasswordsParameter


router = APIRouter(
    prefix="/print-passwords",
    tags=["Print passwords"],
    responses={404: {"description": "Not found"}},
)

@router.get("/schoolclasses", name="Print passwords from schoolclasses")
def print_passwords_schoolclasses(config: PrintPasswordsParameter, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Print passwords from multiple schoolclasses.

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

    for schoolclass in config.schoolclasses:
        get_schoolclass_or_404(schoolclass)

    cmd.extend(['--class', ','.join(config.schoolclasses)])

    try:
        shell_env = {'TERM': 'xterm', 'SHELL': '/bin/bash',  'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',  'HOME': '/root', '_': '/usr/bin/python3'}
        subprocess.check_call(cmd, shell=False, env=shell_env)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=str(e))

    if len(config.schoolclasses) == 1:
        prefix = 'add'
        if config.schoolclasses[0]:
            prefix = config.schoolclasses[0]
    else:
        prefix = 'multiclass'

    filename = f'{prefix}-{who.user}.{config.format}'
    file_path = f'/var/lib/sophomorix/print-data/{filename}'

    return FileResponse(path=file_path, filename=filename, media_type=mtype)




