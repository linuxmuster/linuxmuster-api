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

def check_schoolclass(schoolclass):
    schoolclasses = [s['cn'] for s in lr.get('/schoolclasses', attributes=['cn'])]
    if schoolclass not in schoolclasses:
        raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found")

@router.get("/")
def get_all_schoolclasses(auth: bool = Depends(PermissionChecker("globaladministrator"))):
    """
    Get alls schoolclasses
    """

    return lr.get('/schoolclasses')

@router.get("/{schoolclass}")
def get_schoolclass(schoolclass: str, auth: bool = Depends(PermissionChecker(["globaladministrator"]))):
    """
    Get all details from a specific schoolclass.
    """

    check_schoolclass(schoolclass)

    return lr.get(f'/schoolclasses/{schoolclass}')

@router.get("/{schoolclass}/first_passwords")
def get_schoolclass_passwords(schoolclass: str, auth: bool = Depends(PermissionChecker(["globaladministrator"]))):
    """
    Get all passwords from a specific schoolclass.
    """

    check_schoolclass(schoolclass)

    return lr.get(f'/schoolclasses/{schoolclass}', dict=False).get_first_passwords()

@router.get("/{schoolclass}/students")
def get_schoolclass_passwords(schoolclass: str, auth: bool = Depends(PermissionChecker(["globaladministrator"]))):
    """
    Get all students details from a specific schoolclass.
    """

    check_schoolclass(schoolclass)

    return lr.get(f'/schoolclasses/{schoolclass}/students')