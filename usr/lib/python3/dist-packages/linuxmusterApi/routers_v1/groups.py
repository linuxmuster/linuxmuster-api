import ldap
import logging
from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from .body_schemas import Group, UserList
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNGroup, find_legacy_groups
from linuxmusterTools.common import Validator, NAME_RULES
from utils.checks import get_group_or_404


router = APIRouter(
    prefix="/groups",
    tags=["Groups"],
    responses={404: {"description": "Not found"}},
)

# TODO: cenrtalize
CUSTOMFIELDS = [f'sophomorixCustom{count}' for count in range(1, 5)] + [f'sophomorixCustomMulti{count}' for count in range(1, 5)]

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

@router.get("/legacy", name="List legacy sophomorix-group groups not yet migrated to OU=LMNGroups")
def get_legacy_groups_list(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## List all groups still living in OU=Projects (sophomorixType=sophomorix-group).

    These groups were created by the old `sophomorix-group` CLI and can be moved to
    OU=LMNGroups with `POST /groups/{group}/migrate`.

    For global-administrators, the search will be done in all schools.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of legacy groups details (dict)
    :rtype: list
    """


    return find_legacy_groups(school=who.school)

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


    group_details = get_group_or_404(group, who.school)

    return group_details.as_dict()

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
    """


    get_group_or_404(group, who.school)

    GroupWriter = LMNGroup(group, school=who.school)
    GroupWriter.delete()

@router.post("/{group}", name="Create a new group")
def create_group(group: str, group_details: Group, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Create a new group

    *group_details* are the attributes of the group, like *description*,
    *join* if the group should be joinable, *hide*, etc ...

    ### Attributes for quota

    - `mailquota` is an attribute to add quota for email, as integer (e.g. "mailquota": 100)
    - `quota` is an attribute to add quota per share, as an object. Examples:

    "quota": [{"quota":50,"share":"default-school", "comment":"Need this for videos"}]

    or

    "quota": [{"quota":500,"share":"agy"}, {"quota":300,"share":"linuxmuster-global"}]

    `comment` is optional.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: cn of the group to create
    :type group: basestring
    :param group_details: Parameter of the group, see Group attributes
    :type group_details: Group
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All details of the newly created group (dict)
    :rtype: dict
    """


    if not Validator.check_group_name(group):
        raise HTTPException(status_code=422, detail=f"{group} is not a valid name. Valid chars are {NAME_RULES['group']}")

    school = group_details.school or who.school

    # School specific request. For global-admins, it will search in all groups from all schools
    if lr.get(f'/groups/{group}', school=school):
        raise HTTPException(status_code=400, detail=f"Group {group} already exists on this server.")

    GroupWriter = LMNGroup(group, school=school)

    try:
        GroupWriter.create()
    except ldap.ALREADY_EXISTS:
        raise HTTPException(status_code=400, detail=f"Group {group} already exists on this server.")

    data = {
        'sophomorixHidden': group_details.hide,
        'sophomorixJoinable': group_details.join,
        'sophomorixMailAlias': group_details.mailalias,
        'sophomorixMailList': group_details.maillist,
    }

    if group_details.description:
        data['description'] = group_details.description

    if group_details.displayName:
        data['displayName'] = group_details.displayName

    if group_details.proxyAddresses:
        data['proxyAddresses'] = group_details.proxyAddresses

    if group_details.mailquota is not None:
        data['sophomorixMailQuota'] = [f"{group_details.mailquota}:---:"]

    if group_details.quota:
        data['sophomorixQuota'] = [f"{q.share}:{q.quota}:{q.comment}:" for q in group_details.quota]

    for field in CUSTOMFIELDS:
        value = getattr(group_details, field, None)
        if value:
            data[field] = value

    GroupWriter.setattr(data=data)

    if group_details.members:
        GroupWriter.add_members(group_details.members)

    return GroupWriter.data

@router.patch("/{group}", name="Update the parameters of a specific group")
def modify_group(group: str, group_details: Group, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Update the parameters of a specific group

    *group_details* are the attributes of the group, like *description*,
    *join* if the group should be joinable, *hide*, etc ... and can be partial.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: cn of the group to update
    :type group: basestring
    :param group_details: Parameter of the group, see Group attributes
    :type group_details: Group
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All details of the updated group (dict)
    :rtype: dict
    """


    school = group_details.school or who.school
    get_group_or_404(group, school)

    data = {
        'sophomorixHidden': group_details.hide,
        'sophomorixJoinable': group_details.join,
        'sophomorixMailAlias': group_details.mailalias,
        'sophomorixMailList': group_details.maillist,
    }

    if group_details.description:
        data['description'] = group_details.description

    if group_details.displayName:
        data['displayName'] = group_details.displayName

    if group_details.proxyAddresses:
        data['proxyAddresses'] = group_details.proxyAddresses

    if group_details.mailquota is not None:
        data['sophomorixMailQuota'] = [f"{group_details.mailquota}:---:"]

    if group_details.quota:
        data['sophomorixQuota'] = [f"{q.share}:{q.quota}:{q.comment}:" for q in group_details.quota]

    for field in CUSTOMFIELDS:
        value = getattr(group_details, field, None)
        if value:
            data[field] = value

    GroupWriter = LMNGroup(group, school=school)
    GroupWriter.setattr(data=data)

    if group_details.members:
        GroupWriter.add_members(group_details.members)

    return GroupWriter.data

@router.post("/{group}/members", name="Add users to a specific group")
def add_members_to_group(group: str, userlist: UserList, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Add members to a specific group.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: cn of the group to modify
    :type group: basestring
    :param userlist: List of samaccountname to add
    :type userlist: UserList
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if not userlist.users:
        raise HTTPException(status_code=400, detail="Missing userlist of members to add")

    get_group_or_404(group, who.school)

    GroupWriter = LMNGroup(group, school=who.school)

    for member in userlist.users:
        try:
            GroupWriter.add_member(member)
        except ldap.ALREADY_EXISTS as e:
            if 'Attribute member already exists for target' in str(e):
                # User already member of the group, ignoring
                pass
        except Exception:
            logging.warning(f"User {member} not found, will not add it to group {group}")

@router.delete("/{group}/members", status_code=204, name="Remove users from a specific group")
def remove_members_from_group(group: str, userlist: UserList, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Remove members from a specific group.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: cn of the group to modify
    :type group: basestring
    :param userlist: List of samaccountname to remove
    :type userlist: UserList
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if not userlist.users:
        raise HTTPException(status_code=400, detail="Missing userlist of members to delete")

    get_group_or_404(group, who.school)

    GroupWriter = LMNGroup(group, school=who.school)

    for member in userlist.users:
        try:
            GroupWriter.remove_member(member)
        except ldap.UNWILLING_TO_PERFORM as e:
            if 'Attribute member already deleted for target' in str(e):
                # User already removed from the group, ignoring
                pass
        except Exception:
            logging.warning(f"User {member} not found, will not delete from group {group}")

@router.post("/{group}/migrate", name="Migrate a legacy sophomorix-group to OU=LMNGroups")
def migrate_group(group: str, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Migrate a legacy sophomorix-group (living in OU=Projects) to OU=LMNGroups.

    No-op if the group was already migrated. Group memberships are preserved.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: cn of the group to migrate
    :type group: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: All details of the migrated group (dict)
    :rtype: dict
    """


    get_group_or_404(group, who.school)

    GroupWriter = LMNGroup(group, school=who.school)
    GroupWriter.migrate()

    return GroupWriter.data
