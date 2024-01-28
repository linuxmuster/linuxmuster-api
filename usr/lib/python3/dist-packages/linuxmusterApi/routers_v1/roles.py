from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
import subprocess

from security import PermissionChecker
from utils import lmn_getSophomorixValue
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/roles",
    tags=["Roles"],
    responses={404: {"description": "Not found"}},
)

@router.get("/")
def get_all_roles(auth: bool = Depends(PermissionChecker("globaladministrator"))):
    """
    Get all used roles
    """

    return set([k['sophomorixRole'] for k in lr.get('/search/', attributes=['sophomorixRole']) if k['sophomorixRole']])

@router.get("/{role}")
def get_role_users(user: str, auth: bool = Depends(PermissionChecker(["globaladministrator"]))):
    """
    Get all users having a specific role. A valid role could be teacher, student, globaladministrator,
    schooladministrator, etc ...
    """

    return lr.get(f'/roles/{role}')
