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
    admingroups: list = []
    members: list = []
    membergroups: list = []
    school: str = 'default-school'

class UserList(BaseModel):
    users: list | None = None

@router.get("/")
def get_projects_list(who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    List all projects an user can modify.
    """

    # School specific request. For global-admins, it will return all projects from all schools
    projects = lr.get('/projects', school=who.school)

    if who.role in ["schooladministrator", "globaladministrator"]:
        # No filter
        return projects

    elif who.role == "teacher":
        # Only the teacher's project or not hidden projects or project in which the teacher is member of
        # TODO: read sophomorixMemberGroups too
        response =  []
        for project in projects:
            if who.user in project['sophomorixAdmins'] or who.user in project['sophomorixMembers']:
                response.append(project)
            elif not project['sophomorixHidden']:
                response.append(project)
        return response

@router.get("/{project}")
def get_project_details(project: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    Get informations a bout a specific project.
    """

    # School specific request. For global-admins, it will search in all projects from all schools
    project_details = lr.get(f'/projects/{project}', school=who.school)

    if not project_details:
        raise HTTPException(status_code=404, detail=f"Project {project} not found.")

    if who.role in ["schooladministrator", "globaladministrator"]:
        # No filter
        return project_details

    elif who.role == "teacher":
        # Only the teacher's project or not hidden projects or project in which the teacher is member of
        # TODO: read sophomorixMemberGroups too
        response =  []
        if who.user in project_details['sophomorixAdmins'] or who.user in project_details['sophomorixMembers']:
            return project_details
        elif not project_details['sophomorixHidden']:
            return project_details
        raise HTTPException(status_code=403, detail=f"Forbidden")

@router.delete("/{project}", status_code=204)
def delete_project(project: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    project_details = lr.get(f'/projects/{project}', school=who.school)
    if not project_details:
       raise HTTPException(status_code=404, detail=f"Project {project} not found.")

    cmd = ['sophomorix-project', '--kill', '-p', project, '-jj']
    return lmn_getSophomorixValue(cmd, '')

@router.post("/{project}")
def create_project(project: str, project_details: NewProject, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    if not Validator.check_project_name(project):
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

    for option in ['admins', 'members', 'admingroups', 'membergroups']:
        if getattr(project_details, option):
            options.extend([f'--{option}', ','.join(getattr(project_details, option))])

    if project_details.school:
        options.extend(['--school', project_details.school])

    cmd = ['sophomorix-project',  *options, '--create', '-p', project.lower(), '-jj']
    return lmn_getSophomorixValue(cmd, '')

@router.patch("/{project}")
def modify_project(project: str, project_details: NewProject, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    if not Validator.check_project_name(project):
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

    for option in ['admins', 'members', 'admingroups', 'membergroups']:
        if getattr(project_details, option):
            options.extend([f'--{option}', ','.join(getattr(project_details, option))])

    if project_details.school:
        options.extend(['--school', project_details.school])

    cmd = ['sophomorix-project',  *options, '-p', project.lower(), '-jj']
    return lmn_getSophomorixValue(cmd, '')
