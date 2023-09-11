from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
import subprocess

from security import PermissionChecker
from utils import lmn_getSophomorixValue
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/schoolclasses",
    tags=["Schoolclasses"],
    responses={404: {"description": "Not found"}},
)


@router.get("/")
def get_all_schoolclasses(auth: bool = Depends(PermissionChecker("globaladministrator"))):
    """
    Get alls schoolclasses
    """

    return lr.get('/schoolclasses')

@router.get("/{schoolclass}")
def get_schoolclass(schoolclass: str, auth: bool = Depends(PermissionChecker(["globaladministrator"]))):
    """
    Get all details from a specific user.
    """

    return lr.get(f'/{schoolclass}')

@router.get("/password/{user}/{schoolclass}")
def print_class_password(user: str, schoolclass: str, auth: bool = Depends(PermissionChecker(["teacher"]))):
    cmd = [
        'sophomorix-print', '--school', 'default-school',
        '--caller', user,
        '--template', '/usr/share/sophomorix/lang/latex/templates/datalist-DE-36-template.tex',
        '--class', schoolclass, '-jj'
    ]

    shell_env = {'TERM': 'xterm', 'SHELL': '/bin/bash',  'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',  'HOME': '/root', '_': '/usr/bin/python3'}
    subprocess.check_call(cmd, shell=False, env=shell_env)

    filename = f'{schoolclass}-{user}.pdf'
    file_path = f'/var/lib/sophomorix/print-data/{filename}'

    return FileResponse(path=file_path, filename=filename, media_type='application/pdf')