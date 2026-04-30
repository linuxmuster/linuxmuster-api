from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, UserListChecker, AuthenticatedUser
from .body_schemas import Project
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNProject
from linuxmusterTools.common import Validator, NAME_RULES
from utils.sophomorix import lmn_getSophomorixValue
from utils.checks import get_project_or_404


router = APIRouter(
    prefix="/projects",
    tags=["Projects"],
    responses={404: {"description": "Not found"}},
)

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
        user_details = {}

        for project in projects:
            if who.user in project['sophomorixAdmins'] or who.user in project['sophomorixMembers']:
                response.append(project)
            elif not project['sophomorixHidden']:
                response.append(project)
            else:
                # Digging deeper
                project_groups = project['sophomorixAdminGroups'] + project['sophomorixMemberGroups']

                if not user_details:
                    # Details not already cached
                    user_details = lr.get(f'/users/{who.user}', school=who.school, as_dict=False)

                # User is in a schoolclass member or admin of this project
                if user_details.sophomorixAdminClass in project_groups:
                    response.append(project)

                # User is in a project member or admin of this project
                for p in user_details.projects:
                    if p in project_groups:
                        response.append(project)
        return response

@router.get("/{project}", name="Get all details from a specific project")
def get_project_details(project: str, all_members: bool = False, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Get all details of a specific project.

    The authenticated user can only see projects he's a member of, or not hidden.
    For global-administrators, the search will be done in all schools.
    The optional query parameter `all_members` is a boolean. If set to true, this endpoint will search recusiverly for
    all members in all nested groups (may take a while).

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    \f
    :param project: cn of the project to describe with prefix
    :type project: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all projects details (dict)
    :rtype: list
    """


    project_details = get_project_or_404(project, who, as_dict=False)
    
    if all_members:
        project_details.get_all_members()
    
    project_details = project_details.asdict()

    if all_members:
        project_details['members'] = [lr.get(f'/users/{member}') for member in project_details['all_members']]
        project_details['admins'] = [lr.get(f'/users/{member}') for member in project_details['all_admins']]

    return project_details

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
    :param project: cn of the project to delete with prefix
    :type project: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all projects details (dict)
    :rtype: list
    """


    # Ensure prefix is given
    prefix = "p_"
    if who.school not in ["default-school","global"]:
        prefix = f"p_{who.school}-"

    if not project.startswith(prefix):
        project = prefix + project

    project_details = get_project_or_404(project, who, as_dict=False)

    projectname = project.replace(prefix, "")

    if who.school != "global":
        cmd = ['sophomorix-project', '--kill', '-p', projectname, '--school', who.school, '-jj']
    else:
        cmd = ['sophomorix-project', '--kill', '-p', projectname, '-jj']


    if who.role in ["schooladministrator", "globaladministrator"]:
        # No filter
        return lmn_getSophomorixValue(cmd, '')

    elif who.role == "teacher":
        # Only if the teacher is admin of the project
        # TODO: read sophomorixAdminGroups too
        if who.user in project_details.sophomorixAdmins:
            return lmn_getSophomorixValue(cmd, '')
        raise HTTPException(status_code=403, detail=f"Forbidden")

@router.post("/{project}", name="Create a new project")
def create_project(project: str, project_details: Project, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Create a new project

    *project_details* are the attribute of the project, like *description*,
    *join* if the project should be joinable, *hide*, etc ...

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    ### Attributes for quota

    - `mailquota` is an attribute to add quota for email, as integer (e.g. "mailquota": 100)
    - `quota` is an attribute to add quota per share, as an object. Examples:

    "quota": [{"quota":50,"share":"default-school", "comment":"Need this for videos"}]

    or

    "quota": [{"quota":500,"share":"agy"}, {"quota":300,"share":"linuxmuster-global"}]

    `comment` is optional.

    \f
    :param project: cn of the project to create without prefix p_
    :type project: basestring
    :param project_details: Parameter of the project, see Project attributes
    :type project_details: Project
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all projects details (dict)
    :rtype: list
    """


    options = []

    if not Validator.check_project_name(project):
        raise HTTPException(status_code=422, detail=f"{project} is not a valid name. Valid chars are {NAME_RULES['project']}")

    prefix = "p_"
    if project_details.school:
        if project_details.school not in ["default-school","global"]:
            options.extend(['--school', project_details.school])
            prefix = f"p_{project_details.school}-"

    # School specific request. For global-admins, it will return all projects from all schools
    projects = lr.get('/projects', attributes=['cn'], school=who.school)
    if {'cn': project} in projects or {'cn': f"{prefix}{project}"} in projects:
        raise HTTPException(status_code=400, detail=f"Project {project} already exists on this server.")

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

    if project_details.mailalias:
        options.append('--mailalias')
    else:
        options.append('--nomailalias')

    if project_details.maillist:
        options.append('--maillist')
    else:
        options.append('--nomaillist')

    if project_details.mailquota is not None:
        options.extend(['--addmailquota', f"{project_details.mailquota}:"])

    if project_details.quota:
        quota_to_add = ""
        for q in project_details.quota:
            quota_to_add += f"{q.share}:{q.quota}:{q.comment},"

        options.extend(['--addquota', quota_to_add.strip(',')])

    # Add authenticated user to project admins
    project_details.admins = getattr(project_details, "admins", []) + [who.user]

    for option in ['admins', 'members', 'admingroups', 'membergroups']:
        if getattr(project_details, option):
            options.extend([f'--{option}', ','.join(getattr(project_details, option))])

    # Remove prefix from project name if necessary
    project = project.replace(prefix, "")

    cmd = ['sophomorix-project',  *options, '--create', '-p', project.lower(), '-jj']
    try:
        result =  lmn_getSophomorixValue(cmd, '')
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))

    output = result.get("OUTPUT", [{}])[0]
    if output.get("TYPE", "") == "ERROR":
        raise HTTPException(status_code=400, detail=output["MESSAGE_EN"])

    ProjectWriter = LMNProject(f"{prefix}{project.lower()}", school=who.school)

    if project_details.proxyAddresses:
        ProjectWriter.setattr(data={'proxyAddresses': project_details.proxyAddresses})

    if project_details.displayName:
        ProjectWriter.setattr(data={'displayName': project_details.displayName})
    else:
        ProjectWriter.setattr(data={'displayName': project})

    return result

@router.patch("/{project}", name="Update the parameters of a specific project")
def modify_project(project: str, project_details: Project, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Update the parameters of a specific project

    *project_details* are the attributes of the project, like *description*,
    *join* if the project should be joinable, *hide*, etc ... and can be partial.
    Teachers can only modify a project of which they are admin.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    ### Attributes for quota

    - `mailquota` is an attribute to add quota for email, as integer (e.g. "mailquota": 100)
    - `quota` is an attribute to add quota per share, as an object. Examples:

    "quota": [{"quota":50,"share":"default-school", "comment":"Need this for videos"}]

    or

    "quota": [{"quota":500,"share":"agy"}, {"quota":300,"share":"linuxmuster-global"}]

    `comment` is optional.

    \f
    :param project: cn of the project to update with prefix
    :type project: basestring
    :param project_details: Parameter of the project, see Project attributes
    :type project_details: Project
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """



    prefix = "p_"
    if project_details.school:
        if project_details.school not in ["default-school","global"]:
            prefix = f"p_{project_details.school}-"

    if not project.startswith(prefix):
        project = prefix + project

    project_exists = get_project_or_404(project, who, as_dict=False)

    if who.role == "teacher":
        # Only teacher admins of the group should be able to modify the project
        # TODO: read sophomorixAdminGroups too
        if who.user not in project_exists.sophomorixAdmins:
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

    if project_details.mailalias:
        options.append('--mailalias')
    else:
        options.append('--nomailalias')

    if project_details.maillist:
        options.append('--maillist')
    else:
        options.append('--nomaillist')

    if project_details.mailquota is not None:
        options.extend(['--addmailquota', f"{project_details.mailquota}:"])

    if project_details.quota:
        quota_to_add = ""
        for q in project_details.quota:
            quota_to_add += f"{q.share}:{q.quota}:{q.comment},"

        options.extend(['--addquota', quota_to_add.strip(',')])

    for option in ['admins', 'members', 'admingroups', 'membergroups']:
        if getattr(project_details, option):
            options.extend([f'--{option}', ','.join(getattr(project_details, option))])

    # If --school is specified, sophomorix throw an error 0 project found
    # if project_details.school:
    #     options.extend(['--school', project_details.school])

    # project can be given with or without prefix here
    cmd = ['sophomorix-project',  *options, '-p', project.lower(), '-jj']
    result =  lmn_getSophomorixValue(cmd, '')

    output = result.get("OUTPUT", [{}])[0]
    if output.get("TYPE", "") == "ERROR":
        raise HTTPException(status_code=400, detail=output["MESSAGE_EN"])

    ProjectWriter = LMNProject(f"{project.lower()}", school=who.school)

    if project_details.proxyAddresses:
        ProjectWriter.setattr(data={'proxyAddresses': project_details.proxyAddresses})

    if project_details.displayName:
        ProjectWriter.setattr(data={'displayName': project_details.displayName})

    return result

@router.post("/{project}/join", name="Join an existing project")
def join_project(project: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Join an existing project

    This endpoint let the authenticated user join an existing project, where *project* is the cn of this project, only if
    this project is joinable.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    \f
    :param project: cn of the project to create
    :type project: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    project_details = get_project_or_404(project, who, as_dict=False)

    if who.role == "teacher":
        # Teacher can only join a project if the project is joinable
        if project_details.sophomorixJoinable == False:
            raise HTTPException(status_code=403, detail=f"Project {project} is not joinable.")

    # project can be given with or without prefix here
    cmd = ['sophomorix-project',  '--addmembers', who.user, '-p', project.lower(), '-jj']
    result =  lmn_getSophomorixValue(cmd, '')

    output = result.get("OUTPUT", [{}])[0]
    if output.get("TYPE", "") == "ERROR":
        raise HTTPException(status_code=400, detail=output["MESSAGE_EN"])

    return result

@router.post("/{project}/quit", name="Quit an existing project")
def quit_project(project: str, who: AuthenticatedUser = Depends(RoleChecker("GST"))):
    """
    ## Quit an existing project

    This endpoint let the authenticated user quit an existing project.

    ### Access
    - global-administrators
    - school-administrators
    - teachers

    ### This endpoint uses Sophomorix.

    \f
    :param project: cn of the project to create
    :type project: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    project_details = get_project_or_404(project, who, as_dict=False)

    if who.role == "teacher":
        # Teacher can only join a project if the project is joinable
        if project_details.sophomorixJoinable == False:
            raise HTTPException(status_code=403, detail=f"Project {project} is not joinable, and cannot be quitted.")

    # project can be given with or without prefix here
    cmd = ['sophomorix-project',  '--removemembers', who.user, '--removeadmins', who.user, '-p', project.lower(), '-jj']
    result =  lmn_getSophomorixValue(cmd, '')

    output = result.get("OUTPUT", [{}])[0]
    if output.get("TYPE", "") == "ERROR":
        raise HTTPException(status_code=400, detail=output["MESSAGE_EN"])

    return result
