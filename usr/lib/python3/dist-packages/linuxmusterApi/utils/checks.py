import os
from fastapi import HTTPException

from linuxmusterTools.ldapconnector import LMNLdapReader as lr


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
