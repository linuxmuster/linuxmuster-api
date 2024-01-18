from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
import subprocess

from security import PermissionChecker
from utils import lmn_getSophomorixValue
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/users",
    tags=["Users"],
    responses={404: {"description": "Not found"}},
)

@router.get("/")
def get_all_users(auth: bool = Depends(PermissionChecker("globaladministrator"))):
    """
    Get basic informations from all users
    """

    return lr.get('/users', attributes=['sn', 'givenName', 'sophomorixRole', 'sophomorixAdminClass'])

@router.get("/{user}")
def get_user(user: str, auth: bool = Depends(PermissionChecker(["globaladministrator"]))):
    """
    Get all details from a specific user.
    """

    return lr.get(f'/users/{user}')

