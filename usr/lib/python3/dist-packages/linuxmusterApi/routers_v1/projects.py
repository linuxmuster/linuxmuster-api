import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from security import RoleChecker, UserListChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNLdapWriter as lw
from linuxmusterTools.common import Validator, STRING_RULES
from sophomorix import lmn_getSophomorixValue


router = APIRouter(
    prefix="/projects",
    tags=["Projects"],
    responses={404: {"description": "Not found"}},
)

class NewProject(BaseModel):
    description: str | None = ''
    quota: str = ''
    mailquota: str = ''
    join: bool = True
    hide: bool = False
    admins: list = []
    school: str = 'default-school'

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

@router.post("/{project}")
def create_project(project: str, project_details: NewProject, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    if not Validator.check_session(project):
        raise HTTPException(status_code=422, detail=f"{project} is not a valid name. Valid chars are {STRING_RULES['project']}")

    options = []

    if project_details.description:
        options.extend(['--description', project_details.description])

    if project_details.join:
        options.append('--join')
    else:
        options.append('--nojoin')

    if project_details.hide:
        options.append('--hide')
    else:
        options.append('--nohide')

    if project_details.admins:
        options.extend(['--admins', ','.join(project_details.admins)])

    if project_details.school:
        options.extend(['--school', project_details.school])

    cmd = ['sophomorix-project',  *options, '--create', '-p', project.lower(), '-jj']
    return lmn_getSophomorixValue(cmd, '')
