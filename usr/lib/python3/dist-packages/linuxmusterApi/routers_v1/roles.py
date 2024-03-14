from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
import subprocess

from security import RoleChecker
from utils import lmn_getSophomorixValue
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/roles",
    tags=["Roles"],
    responses={404: {"description": "Not found"}},
)

@router.get("/")
def get_all_roles(auth: bool = Depends(RoleChecker("GS"))):
    """
    Get all used roles
    """

    return set([k['sophomorixRole'] for k in lr.get('/search/', attributes=['sophomorixRole']) if k['sophomorixRole']])

@router.get("/{role}")
def get_role_users(role: str, school: str | None = 'default-school', auth: bool = Depends(RoleChecker(["GS"]))):
    """
    Get all users having a specific role. A valid role could be teacher, student, globaladministrator,
    schooladministrator, etc ...
    """

    if 'global' in role:
        return lr.get(f'/roles/{role}')

    return lr.get(f'/roles/{role}', school=school)

