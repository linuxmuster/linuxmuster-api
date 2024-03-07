from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
import subprocess

from security import PermissionChecker
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/teachers",
    tags=["Teachers"],
    responses={404: {"description": "Not found"}},
)


def check_teacher(teacher):
    teachers = [s['cn'] for s in lr.get('/roles/teacher', attributes=['cn'])]
    if teacher not in teachers:
        raise HTTPException(status_code=404, detail=f"Teacher {teacher} not found")

@router.get("/")
def get_all_teachers(auth: bool = Depends(PermissionChecker("GS"))):
    """
    Get basic informations from all teachers
    """

    return lr.get('/roles/teacher')

@router.get("/{teacher}")
def get_teacher(teacher: str, auth: bool = Depends(PermissionChecker("GS"))):
    """
    Get all details from a specific teacher.
    """

    check_teacher(teacher)

    return lr.get(f'/users/{teacher}')

