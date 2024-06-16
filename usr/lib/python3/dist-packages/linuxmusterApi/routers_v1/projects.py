import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from security import RoleChecker, UserListChecker, AuthenticatedUser
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNLdapWriter as lw
from linuxmusterTools.common import Validator, STRING_RULES
from utils.sophomorix import lmn_getSophomorixValue


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

@router.get("/", name="List all projects the authenticated user can see")
def get_projects_list(who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## List all details of all projects.

    The authenticated user can only see projects he's a member of, or not hidden.
    For global-administrators, the search will be done in all schools.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all projects details (dict)
    :rtype: list
    """


    # School specific request. For global-admins, it will return all projects from all schools
    projects = lr.get('/projects', school=who.school)

    if who.role in ["schooladministrator", "globaladministrator"]:
        # No filter
        return projects

    elif who.role == "teacher":
        # Only the teacher's project or not hidden projects or project in which the teacher is member of
        # TODO: read sophomorixMemberGroups and sophomorixAdminGroups too
        response =  []
        for project in projects:
            if who.user in project['sophomorixAdmins'] or who.user in project['sophomorixMembers']:
                response.append(project)
            elif not project['sophomorixHidden']:
                response.append(project)
        return response

@router.get("/{project}", name="Get all details from a specific project")
def get_project_details(project: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Get all details of a specific project.

    The authenticated user can only see projects he's a member of, or not hidden.
    For global-administrators, the search will be done in all schools.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param project: cn of the project to describe
    :type project: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all projects details (dict)
    :rtype: list
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
        # TODO: read sophomorixMemberGroups and sophomorixAdminGroups too
        response =  []
        if who.user in project_details['sophomorixAdmins'] or who.user in project_details['sophomorixMembers']:
            return project_details
        elif not project_details['sophomorixHidden']:
            return project_details
        raise HTTPException(status_code=403, detail=f"Forbidden")

@router.delete("/{project}", status_code=204, name="Delete a specific project")
def delete_project(project: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Delete a specific project

    The authenticated user can only delete a project if he's a admin of, or if
    he's an admin.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    \f
    :param project: cn of the project to delete
    :type project: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all projects details (dict)
    :rtype: list
    """


    # School specific request. For global-admins, it will search in all projects from all schools
    project_details = lr.get(f'/projects/{project}', school=who.school)

    if not project_details:
       raise HTTPException(status_code=404, detail=f"Project {project} not found.")

    cmd = ['sophomorix-project', '--kill', '-p', project, '--school', who.school, '-jj']

    if who.role in ["schooladministrator", "globaladministrator"]:
        # No filter
        return lmn_getSophomorixValue(cmd, '')

    elif who.role == "teacher":
        # Only if the teacher is admin of the project
        # TODO: read sophomorixAdminGroups too
        if who.user in project_details['sophomorixAdmins']:
            return lmn_getSophomorixValue(cmd, '')
        raise HTTPException(status_code=403, detail=f"Forbidden")

@router.post("/{project}", name="Create a new project")
def create_project(project: str, project_details: NewProject, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Create a new project

    *project_details* are the attribute of the project, like *description*,
    *join* if the project should be joinable, *hide*, etc ...

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    \f
    :param project: cn of the project to create
    :type project: basestring
    :param project_details: Parameter of the project, see NewProject attributes
    :type project_details: NewProject
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all projects details (dict)
    :rtype: list
    """


    if not Validator.check_project_name(project):
        raise HTTPException(status_code=422, detail=f"{project} is not a valid name. Valid chars are {STRING_RULES['project']}")

    # School specific request. For global-admins, it will return all projects from all schools
    projects = lr.get('/projects', attributes=['cn'], school=who.school)
    if {'cn': project} in projects or {'cn': f"p_{project}"} in projects:
        raise HTTPException(status_code=400, detail=f"Project {project} already exists on this server.")

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

@router.patch("/{project}", name="Update the parameters of a specific project")
def modify_project(project: str, project_details: NewProject, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Update the parameters of a specific project

    *project_details* are the attribute of the project, like *description*,
    *join* if the project should be joinable, *hide*, etc ... and can be partial.
    Teachers can only modify a project of which they are admin.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    \f
    :param project: cn of the project to update
    :type project: basestring
    :param project_details: Parameter of the project, see NewProject attributes
    :type project_details: NewProject
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all projects details (dict)
    :rtype: list
    """


    # School specific request. For global-admins, it will search in all projects from all schools
    project_details = lr.get(f'/projects/{project}', school=who.school)

    if not project_details:
       raise HTTPException(status_code=404, detail=f"Project {project} not found.")

    if who.role == "teacher":
        # Only teacher admins of the group should be able to modify the project
        # TODO: read sophomorixAdminGroups too
        if who.user not in project_details['sophomorixAdmins']:
            raise HTTPException(status_code=403, detail=f"Forbidden")

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
