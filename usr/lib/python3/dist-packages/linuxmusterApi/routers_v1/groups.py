from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, UserListChecker, AuthenticatedUser
from .body_schemas import UserList, NewProject as NewGroup
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNLdapWriter as lw
from linuxmusterTools.common import Validator, STRING_RULES


router = APIRouter(
    prefix="/groups",
    tags=["Groups"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", name="List all groups")
def get_groups_list(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## List all details of all groups.

    For global-administrators, the search will be done in all schools.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all groups details (dict)
    :rtype: list
    """


    # School specific request. For global-admins, it will return all groups from all schools
    return lr.get('/groups', school=who.school)

@router.get("/{group}", name="Get all details from a specific group")
def get_group_details(group: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get all details of a specific group.

    For global-administrators, the search will be done in all schools.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: cn of the group to describe
    :type group: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all groups details (dict)
    :rtype: list
    """


    # School specific request. For global-admins, it will search in all groups from all schools
    group_details = lr.get(f'/groups/{group}', school=who.school)

    if not group_details:
        raise HTTPException(status_code=404, detail=f"Group {group} not found.")

    return group_details

@router.delete("/{group}", status_code=204, name="Delete a specific group")
def delete_group(group: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Delete a specific group

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: cn of the group to delete
    :type group: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all groups details (dict)
    :rtype: list
    """


    # School specific request. For global-admins, it will search in all groups from all schools
    group_details = lr.get(f'/groups/{group}', school=who.school)

    if not group_details:
       raise HTTPException(status_code=404, detail=f"Group {group} not found.")

    # TODO: add delete_unit in linuxmuster-tools

@router.post("/{group}", name="Create a new group")
def create_group(group: str, group_details: NewGroup, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Create a new group

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: cn of the group to create
    :type group: basestring
    :param group_details: Parameter of the group, see NewGroup attributes
    :type group_details: NewGroup
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all groups details (dict)
    :rtype: list
    """


    if not Validator.check_group_name(group):
        raise HTTPException(status_code=422, detail=f"{group} is not a valid name. Valid chars are {STRING_RULES['group']}")

    # School specific request. For global-admins, it will return all groups from all schools
    groups = lr.get('/groups', attributes=['cn'], school=who.school)
    if {'cn': group} in groups or {'cn': f"p_{group}"} in groups:
        raise HTTPException(status_code=400, detail=f"Group {group} already exists on this server.")

    options = []

    if group_details.description:
        options.extend(['--description', group_details.description])

    if group_details.join:
        options.append('--join')
    else:
        options.append('--nojoin')

    if group_details.hide:
        options.append('--hide')
    else:
        options.append('--nohide')

    for option in ['admins', 'members', 'admingroups', 'membergroups']:
        if getattr(group_details, option):
            options.extend([f'--{option}', ','.join(getattr(group_details, option))])

    if group_details.school:
        options.extend(['--school', group_details.school])

    # TODO: add add_unit to linuxmuster-tools

@router.patch("/{group}", name="Update the parameters of a specific group")
def modify_group(group: str, group_details: NewGroup, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Update the parameters of a specific group

    *group_details* are the attribute of the group, like *description*,
    *join* if the group should be joinable, *hide*, etc ... and can be partial.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: cn of the group to update
    :type group: basestring
    :param group_details: Parameter of the group, see NewGroup attributes
    :type group_details: NewGroup
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all groups details (dict)
    :rtype: list
    """


    # School specific request. For global-admins, it will search in all groups from all schools
    group_details = lr.get(f'/groups/{group}', school=who.school)

    if not group_details:
       raise HTTPException(status_code=404, detail=f"Group {group} not found.")

    if who.role == "teacher":
        # Only teacher admins of the group should be able to modify the group
        # TODO: read sophomorixAdminGroups too
        if who.user not in group_details['sophomorixAdmins']:
            raise HTTPException(status_code=403, detail=f"Forbidden")

    options = []

    if group_details.description:
        options.extend(['--description', group_details.description])

    if group_details.join:
        options.append('--join')
    else:
        options.append('--nojoin')

    if group_details.hide:
        options.append('--hide')
    else:
        options.append('--nohide')

    for option in ['admins', 'members', 'admingroups', 'membergroups']:
        if getattr(group_details, option):
            options.extend([f'--{option}', ','.join(getattr(group_details, option))])

    if group_details.school:
        options.extend(['--school', group_details.school])

    # TODO
