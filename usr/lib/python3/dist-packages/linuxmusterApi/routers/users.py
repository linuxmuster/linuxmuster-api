from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
import subprocess

from security import PermissionChecker
from utils import lmn_getSophomorixValue
from linuxmusterTools.ldapconnector.connector import LdapConnector
from linuxmusterTools.ldapconnector.models import LMNUser


router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)

lc = LdapConnector()

@router.get("/")
def get_all_users(auth: bool = Depends(PermissionChecker("globaladministrator"))):
    return "ALL"

@router.get("/{user}")
def get_user_details(user: str, auth: bool = Depends(PermissionChecker(["schooladministrator", "globaladministrator"]))):
    cmd = f"sophomorix-user -ivvv -u {user} -jj".split()
    return lmn_getSophomorixValue(cmd, '')

@router.post("/testrootperm")
def test_root_perm(auth: bool = Depends(PermissionChecker(["student"]))):
    cmd = f"touch /root/testapi.log".split()
    subprocess.check_call(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    return "ok"

@router.get("/lr/{user}")
def test_root_perm(user: str, auth: bool = Depends(PermissionChecker(["student"]))):
    """
    Get all details from a specific user.
    Return a LMNUser data object.
    """

    ldap_filter = f"""(&
                                (cn={user})
                                (objectClass=user)
                                (|
                                    (sophomorixRole=globaladministrator)
                                    (sophomorixRole=schooladministrator)
                                    (sophomorixRole=teacher)
                                    (sophomorixRole=student)
                                )
                            )"""

    return lc.get_single(LMNUser, ldap_filter)

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
