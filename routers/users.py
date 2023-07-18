from fastapi import APIRouter, Depends, HTTPException, Request
import subprocess

from security import PermissionChecker
from utils import lmn_getSophomorixValue
from ldapconnector.connector import LdapConnector
from ldapconnector.models import LMNUser


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