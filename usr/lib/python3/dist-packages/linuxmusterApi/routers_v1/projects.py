import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from security import RoleChecker, UserListChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNLdapWriter as lw
from sophomorix import lmn_getSophomorixValue


router = APIRouter(
    prefix="/projects",
    tags=["Projects"],
    responses={404: {"description": "Not found"}},
)

class UserList(BaseModel):
    users: list | None = None

@router.get("/")
def get_projects_list(who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    List all projects an user can modify.
    """

    return lr.get('/projects', school=who.school)

@router.get("/{project}")
def get_project_details(project: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    Get informations a bout a specific project.
    """

    project_details = lr.get(f'/projects/{project}', school=who.school)

    if project_details:
        return project_details

    raise HTTPException(status_code=404, detail=f"Project {project} not found.")

@router.delete("/{project}", status_code=204)
def delete_project(project: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    project_details = lr.get(f'/projects/{project}', school=who.school)
    if not project_details:
       raise HTTPException(status_code=404, detail=f"Project {project} not found.")

    cmd = ['sophomorix-project', '--kill', '-p', project, '-jj']
    return lmn_getSophomorixValue(cmd, '')

