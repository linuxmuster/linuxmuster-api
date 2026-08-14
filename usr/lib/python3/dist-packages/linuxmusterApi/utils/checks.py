import logging
import os
from functools import wraps
from pathlib import Path

from fastapi import HTTPException

from linuxmusterTools.common.checks import NameChecker
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.linbo import ImageExistsError, IncompleteImageInfoError, LINBO_PATH, timestamp2date
from linuxmusterTools.passwords import PasswordRules


logger = logging.getLogger(__name__)
linbo_name_checker = NameChecker()


def check_tmp_dir():
    # Ensure tmp directory is ready
    if not os.path.exists('/tmp/lmnapi'):
        os.makedirs('/tmp/lmnapi')
        os.chmod('/tmp/lmnapi', 0o600)

def get_user_or_404(user, school):
    try:
        user_details = lr.get(f'/users/{user}', school=school, as_dict=False)
    except Exception as err:
        raise HTTPException(status_code=404, detail=f"User {user} not found in ldap tree: {str(err)}")

    if not user_details.cn:
        raise HTTPException(status_code=404, detail=f"User {user} not found in ldap tree.")

    return user_details

def get_schoolclass_or_404(schoolclass, who, as_dict=True):
    """
    Check if a schoolclass exist and if the authenticated user can see it: only if the attribute sophomorixHidden is
    not true, or if the user is already admin of the schoolclass.

    :param schoolclass: Schoolclass name
    :param who: Authenticated user
    :return: Schoolclass details
    """


    try:
        schoolclass_data = lr.get(f'/schoolclasses/{schoolclass}', school=who.school, as_dict=as_dict)
    except Exception as err:
        raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found: {str(err)}")

    if not schoolclass_data:
        raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found")

    if as_dict:
        admins = schoolclass_data['sophomorixAdmins']
        hidden = schoolclass_data['sophomorixHidden']
    else:
        admins = schoolclass_data.sophomorixAdmins
        hidden = schoolclass_data.sophomorixHidden

    if who.role in ["schooladministrator", "globaladministrator"]:
        return schoolclass_data
    elif who.role == "teacher":
        if who.user in admins:
            return schoolclass_data
        elif not hidden:
            return schoolclass_data
    else:
        raise HTTPException(status_code=403, detail=f"Forbidden")

def get_extraclass_or_404(schoolclass, school):
    try:
        schoolclass_data = lr.get(f'/extraclasses/{schoolclass}', school=school)
    except Exception as err:
        raise HTTPException(status_code=404, detail=f"Extraclass {schoolclass} not found: {str(err)}")

    if not schoolclass_data:
        raise HTTPException(status_code=404, detail=f"Extraclass {schoolclass} not found")

    return schoolclass_data

def get_teacher_or_404(teacher, school):
    try:
        user = lr.get(f'/users/{teacher}', school=school)
    except Exception as err:
        raise HTTPException(status_code=404, detail=f"Teacher {teacher} not found: {str(err)}")

    if user.get('sophomorixAdminClass', '') != "teachers":
        raise HTTPException(status_code=404, detail=f"Teacher {teacher} not found")

    return user

def get_project_or_404(project, who, as_dict=True):
    """
    Check if a project exist and if the authenticated user can see it: only if the attribute sophomorixHidden is
    not true, or if the user is already admin of the project.

    :param project: Project name
    :param who: Authenticated user
    :return: Project details
    """


    # Ensure prefix is given
    prefix = "p_"
    if who.school not in ["default-school", "global"]:
        prefix = f"p_{who.school}-"

    if not project.startswith(prefix):
        project = prefix + project

    try:
        project_data = lr.get(f'/projects/{project}', school=who.school, as_dict=as_dict)
    except Exception as err:
        raise HTTPException(status_code=404, detail=f"Project {project} not found: {str(err)}")

    if not project_data:
        raise HTTPException(status_code=404, detail=f"Project {project} not found")

    if as_dict:
        admins = project_data['sophomorixAdmins']
        groupadmins = project_data['sophomorixAdminGroups']
        members = project_data['sophomorixMembers']
        groupmembers = project_data['sophomorixMemberGroups']
        hidden = project_data['sophomorixHidden']
    else:
        admins = project_data.sophomorixAdmins
        groupadmins = project_data.sophomorixAdminGroups
        members = project_data.sophomorixMembers
        groupmembers = project_data.sophomorixMemberGroups
        hidden = project_data.sophomorixHidden

    if who.role in ["schooladministrator", "globaladministrator"]:
        return project_data
    else:
        # TODO missing check in nested groups
        if who.user in admins or who.user in members:
            return project_data
        elif not hidden:
            return project_data
        else:
            # Digging deeper
            user_details = lr.get(f'/users/{who.user}', school=who.school, as_dict=False)

            # User is in a schoolclass member or admin of this project
            if user_details.sophomorixAdmincClass in groupadmins + groupmembers:
                return project_data

            # User is in a project member or admin of this project
            for p in user_details.projects:
                if p in groupadmins + groupmembers:
                    return project_data

        raise HTTPException(status_code=403, detail=f"Forbidden")

def get_group_or_404(group, school):
    """
    Check if a group (sophomorix-group) exists. Access to /v1/groups is
    restricted to admins, so there is no visibility logic to apply here,
    unlike get_project_or_404 or get_schoolclass_or_404.

    :param group: Group cn
    :param school: School to search in (or "global" for global-administrators)
    :return: Group details
    """


    try:
        group_details = lr.get(f'/groups/{group}', school=school, as_dict=False)
    except Exception as err:
        raise HTTPException(status_code=404, detail=f"Group {group} not found: {str(err)}")

    if not group_details.cn:
        raise HTTPException(status_code=404, detail=f"Group {group} not found")

    return group_details

def get_printer_or_404(printer, school):
    try:
        printer_details = lr.get(f'/printers/{printer}', attributes=['cn'], school=school, as_dict=False)
    except Exception as err:
        raise HTTPException(status_code=404, detail=f"Printer {printer} not found: {str(err)}")

    if not printer_details.cn:
        raise HTTPException(status_code=404, detail=f"Printer {printer} not found")

    return printer_details

def check_valid_school_or_404(school):
    """
    Check if the given school is a valid school.
    """

    if school not in lr.getval('/schools', 'ou'):
        raise HTTPException(status_code=404,
                            detail=f"{school} is not a valid school")

    return school

def require_school(func):
    """
    Decorator for endpoints taking a `who` (AuthenticatedUser) and a `school`
    parameter. A global-administrator (who.school == 'global') is not scoped to
    a single school, so the endpoint must receive an explicit, valid `school`
    argument to know which school to operate on. Without this, a school-scoped
    value like 'global' can end up passed to a LDAP writer (e.g. LMNGroup) and
    fail deep in the call stack instead of at the API boundary.

    A school-administrator is scoped to their own school: if they pass a
    `school` different from `who.school`, the request is rejected instead of
    silently operating on another school.

    Only applies to endpoints whose `school` is a direct parameter (not nested
    in a body schema, e.g. `group_details.school`).

    :raises HTTPException 400: who.school == 'global' and no school was given
    :raises HTTPException 403: who.school != 'global' and school != who.school
    :raises HTTPException 404: the given school is not a valid school
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        who = kwargs.get('who')
        school = kwargs.get('school') or ''

        if who is not None and who.school != 'global':
            if school and school != who.school:
                raise HTTPException(
                    status_code=403,
                    detail="school-administrators can only operate on their own school."
                )
            return func(*args, **kwargs)

        if not school:
            raise HTTPException(
                status_code=400,
                detail="A specific school is required: global-administrators must provide the 'school' parameter."
            )

        check_valid_school_or_404(school)

        return func(*args, **kwargs)

    return wrapper

def check_valid_mgmtlist_or_404(mgmtlist, school):
    """
    Check if the given mgmtlist name exists and returns the path of the CSV file.
    """


    if mgmtlist not in ['students','teachers','parents','staff','extraclasses','extrastudents']:
        raise HTTPException(status_code=404, detail=f"{mgmtlist} is not a valid role")

    check_valid_school_or_404(school)

    if school == "default-school":
        configpath = f'/etc/linuxmuster/sophomorix/default-school/{mgmtlist}.csv'
    else:
        configpath = f'/etc/linuxmuster/sophomorix/{school}/{school}.{mgmtlist}.csv'

    # Ensure file exists
    if os.path.isfile(configpath) is False:
        os.mknod(configpath)

    return configpath

def check_password_constraints_rules_or_400(role: str, entries: list):
    for entry in entries:
        try:
            PasswordRules.build(entry)
        except Exception as e:
            raise HTTPException(status_code=400,
                                detail=f"Invalid rule for role '{role}': {e}")

def check_linbo_image_group_or_404(manager, image_name):
    """
    Resolve a LINBO image group by name. LinboImageManager's own operations
    (delete, rename, restore, save_extras) silently do nothing for an unknown
    group, so callers must resolve it first to answer 404 themselves.

    An image whose .info is unreadable is refused with 409: LinboImageGroup.load()
    stops in that case, leaving base as None and diff_image never assigned, so
    touching group.diff_image would raise AttributeError.

    :param manager: LinboImageManager instance
    :param image_name: Name of the LINBO image
    :return: The resolved LinboImageGroup
    """


    group = manager.groups.get(image_name)
    if group is None:
        raise HTTPException(status_code=404, detail=f"No image named {image_name}")

    if group.base is None:
        raise HTTPException(status_code=409, detail=f"Image {image_name} is not usable: {group.error}")

    return group

def check_new_linbo_image_name_or_409(manager, new_name):
    """
    Validate a name for a new LINBO image (rename/duplicate target). Unlike
    check_linbo_image_group_or_404, new_name is about to be used to build a
    filesystem path and become a real directory name, so its format is
    validated here.

    :param manager: LinboImageManager instance
    :param new_name: Candidate name
    :return: The validated name
    """


    if not linbo_name_checker.check_linbo_image_name(new_name):
        raise HTTPException(status_code=400, detail=f"Invalid image name: {new_name}")

    if new_name in manager.groups or Path(LINBO_PATH, new_name).exists():
        raise HTTPException(status_code=409, detail=f"An image named {new_name} already exists")

    return new_name

def check_linbo_backup_date_or_404(group, timestamp):
    """
    Resolve a %Y%m%d%H%M path segment to the display date LinboImageGroup keys
    its backups by. The manager's delete/restore take that display form, while
    save_extras takes the raw timestamp — endpoints always take the raw
    timestamp and convert here, so the URL shape stays uniform.

    :param group: LinboImageGroup instance
    :param timestamp: Backup timestamp, YYYYMMDDhhmm
    :return: The display-form date key into group.backups
    """


    try:
        date = timestamp2date(timestamp)
    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid backup timestamp {timestamp}, expected YYYYMMDDhhmm",
        ) from error

    if date not in group.backups:
        raise HTTPException(status_code=404, detail=f"No backup {timestamp} for image {group.name}")

    return date

def run_linbo_image_operation(operation):
    """
    Run a LinboImageManager mutation and map its failure modes onto status
    codes. RuntimeError is what LinboImageGroup raises for a group whose
    .info is missing or incomplete: the image exists but cannot be operated
    on. This is not a check: it executes the operation rather than
    validating input ahead of it.

    :param operation: Zero-argument callable performing the actual mutation
    :return: Whatever operation() returns
    """


    try:
        return operation()
    except ImageExistsError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except IncompleteImageInfoError as error:
        # rename and duplicate re-read the .info they just rewrote. If that
        # read fails the operation has already half-happened, so this is a
        # server-side inconsistency to report, not a bad request to reject.
        logger.error("LINBO image left unreadable after an operation: %r", error)
        raise HTTPException(status_code=500, detail=f"Image is no longer readable: {error}") from error
    except OSError as error:
        logger.error("LINBO image operation failed: %r", error)
        raise HTTPException(status_code=500, detail=f"Image operation failed: {error}") from error