import ldap
import logging
from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from .body_schemas import Group, GroupList, UserList
from linuxmusterTools.ldapconnector import LMNLdapReader as lr, LMNGroup, find_legacy_groups
from linuxmusterTools.common import Validator, NAME_RULES
from utils.checks import get_group_or_404, get_dn_or_404, require_school, check_valid_school_or_404


router = APIRouter(
    prefix="/groups",
    tags=["Groups"],
    responses={404: {"description": "Not found"}},
)

# TODO: cenrtalize
CUSTOMFIELDS = [f'sophomorixCustom{count}' for count in range(1, 5)] + [f'sophomorixCustomMulti{count}' for count in range(1, 5)]

def check_membergroups_or_4xx(group, membergroups, school):
    """
    Resolve every member group before writing anything: a partial refusal
    would let the caller believe the whole request went through. The writer
    resolves them again, cheaply, when it applies them.

    :param group: cn of the group which gets the member groups
    :param membergroups: List of cn of the member groups
    :param school: School of the group, the member groups must be in it too
    :raises HTTPException: 400 for the group itself, 404 for an unknown group
    """


    for membergroup in membergroups:
        if membergroup.lower() == group.lower():
            raise HTTPException(status_code=400, detail=f"Group {group} can not be a member of itself")

        get_dn_or_404('units', membergroup, 'Group', school=school)

def raise_on_membergroup_failures(group, failures):
    """
    Turn the failures reported by the writer into an error naming each group.

    :param group: cn of the modified group
    :param failures: list of (group, error message) tuples from the writer
    :raises HTTPException: 500 if any member group could not be written
    """


    if failures:
        detail = ", ".join(f"{membergroup}: {error}" for membergroup, error in failures)
        raise HTTPException(status_code=500, detail=f"Could not update the member groups of {group}: {detail}")

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
@require_school
def delete_group(group: str, school: str = '', who: AuthenticatedUser = Depends(RoleChecker("GS"))):
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


    active_school = school if school else who.school
    get_group_or_404(group, active_school)

    GroupWriter = LMNGroup(group, school=active_school)
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

    ### Members

    - `members` is a list of users (samaccountname)
    - `membergroups` is a list of schoolclasses, projects or groups of the same
    school, whose members become members of this group

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

    # school-administrators are restricted to their own school: group_details.school
    # is only honored for global-administrators, who are not scoped to a single school.
    school = group_details.school if who.school == 'global' else who.school

    # School specific request. For global-admins, it will search in all groups from all schools
    if lr.get(f'/groups/{group}', school=school):
        raise HTTPException(status_code=400, detail=f"Group {group} already exists on this server.")

    check_valid_school_or_404(school)
    check_membergroups_or_4xx(group, group_details.membergroups, school)
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

    if group_details.membergroups:
        raise_on_membergroup_failures(group, GroupWriter.add_membergroups(group_details.membergroups))

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


    # school-administrators are restricted to their own school: group_details.school
    # is only honored for global-administrators, who are not scoped to a single school.
    school = group_details.school if who.school == 'global' else who.school
    check_valid_school_or_404(school)
    get_group_or_404(group, school)
    check_membergroups_or_4xx(group, group_details.membergroups, school)

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

    if group_details.membergroups:
        raise_on_membergroup_failures(group, GroupWriter.add_membergroups(group_details.membergroups))

    return GroupWriter.data

@router.post("/{group}/members", name="Add users to a specific group")
@require_school
def add_members_to_group(group: str, userlist: UserList, school: str = '', who: AuthenticatedUser = Depends(RoleChecker("GS"))):
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

    active_school = school if school else who.school
    get_group_or_404(group, active_school)

    GroupWriter = LMNGroup(group, school=active_school)

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
@require_school
def remove_members_from_group(group: str, userlist: UserList, school: str = '', who: AuthenticatedUser = Depends(RoleChecker("GS"))):
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

    active_school = school if school else who.school
    get_group_or_404(group, active_school)

    GroupWriter = LMNGroup(group, school=active_school)

    for member in userlist.users:
        try:
            GroupWriter.remove_member(member)
        except ldap.UNWILLING_TO_PERFORM as e:
            if 'Attribute member already deleted for target' in str(e):
                # User already removed from the group, ignoring
                pass
        except Exception:
            logging.warning(f"User {member} not found, will not delete from group {group}")

@router.post("/{group}/membergroups", name="Add groups as members of a specific group")
@require_school
def add_membergroups_to_group(group: str, grouplist: GroupList, school: str = '', who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Add groups as members of a specific group.

    The groups are schoolclasses, projects or groups of the same school. Their
    members become members of this group through the directory, so a later
    change in a member group needs no further request.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: cn of the group to modify
    :type group: basestring
    :param grouplist: List of cn of the groups to add
    :type grouplist: GroupList
    :param school: School of the group, required for global-administrators
    :type school: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if not grouplist.groups:
        raise HTTPException(status_code=400, detail="Missing list of groups to add")

    active_school = school if school else who.school
    get_group_or_404(group, active_school)
    check_membergroups_or_4xx(group, grouplist.groups, active_school)

    GroupWriter = LMNGroup(group, school=active_school)
    raise_on_membergroup_failures(group, GroupWriter.add_membergroups(grouplist.groups))

@router.delete("/{group}/membergroups", status_code=204, name="Remove groups from the members of a specific group")
@require_school
def remove_membergroups_from_group(group: str, grouplist: GroupList, school: str = '', who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Remove groups from the members of a specific group.

    The users which are direct members of this group stay, even if they are
    also members of a removed group.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param group: cn of the group to modify
    :type group: basestring
    :param grouplist: List of cn of the groups to remove
    :type grouplist: GroupList
    :param school: School of the group, required for global-administrators
    :type school: basestring
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    if not grouplist.groups:
        raise HTTPException(status_code=400, detail="Missing list of groups to remove")

    active_school = school if school else who.school
    get_group_or_404(group, active_school)

    for membergroup in grouplist.groups:
        get_dn_or_404('units', membergroup, 'Group', school=active_school)

    GroupWriter = LMNGroup(group, school=active_school)
    raise_on_membergroup_failures(group, GroupWriter.remove_membergroups(grouplist.groups))

@router.post("/{group}/migrate", name="Migrate a legacy sophomorix-group to OU=LMNGroups")
@require_school
def migrate_group(group: str, school: str = '', who: AuthenticatedUser = Depends(RoleChecker("GS"))):
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


    active_school = school if school else who.school
    get_group_or_404(group, active_school)

    GroupWriter = LMNGroup(group, school=active_school)
    GroupWriter.migrate()

    return GroupWriter.data
