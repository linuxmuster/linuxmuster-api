from fastapi import HTTPException

from linuxmusterTools.ldapconnector import LMNLdapReader as lr


def get_user_or_404(user, school):
    try:
        user_details = lr.get(f'/users/{user}', school=school, dict=False)
        if not user_details.cn:
            raise HTTPException(status_code=404, detail=f"User {user} not found in ldap tree.")
        return user_details
    except Exception:
        raise HTTPException(status_code=404, detail=f"User {user} not found in ldap tree.")

def get_schoolclass_or_404(schoolclass, who, dict=False):
    """
    Check if a schoolclass exist and if the authenticated user can see it: only if the attribute sophomorixHidden is
    not true, or if the user is already admin of the schoolclass.

    :param schoolclass: Schoolclass name
    :param who: Authenticated user
    :return: Schoolclass details
    """


    try:
        schoolclass_data = lr.get(f'/schoolclasses/{schoolclass}', school=who.school, dict=dict)

        if dict:
            admins = schoolclass_data['sophomorixAdmins']
            hidden = schoolclass_data['sophomorixHidden']
        else:
            admins = schoolclass_data.sophomorixAdmins
            hidden = schoolclass_data.sophomorixHidden

        if not schoolclass_data:
            raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found")
        if who.role in ["schooladministrator", "globaladministrator"]:
            return schoolclass_data
        elif who.role == "teacher":
            if who.user in admins:
                return schoolclass_data
            elif not hidden:
                return schoolclass_data
        else:
            raise HTTPException(status_code=403, detail=f"Forbidden")
    except Exception as err:
        print(str(err))
        raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found")

def get_extraclass_or_404(schoolclass, school):
    try:
        schoolclass_data = lr.get(f'/extraclasses/{schoolclass}', school=school)
        if not schoolclass_data:
            raise HTTPException(status_code=404, detail=f"Extraclass {schoolclass} not found")
        return schoolclass_data
    except Exception:
        raise HTTPException(status_code=404, detail=f"Extraclass {schoolclass} not found")

def get_teacher_or_404(teacher, school):
    try:
        user = lr.get(f'/users/{teacher}', school=school)
        if user.get('sophomorixAdminClass', '') != "teachers":
            raise HTTPException(status_code=404, detail=f"Teacher {teacher} not found")
        return user
    except Exception:
        raise HTTPException(status_code=404, detail=f"Teacher {teacher} not found")

def get_project_or_404(project, school):
    """

    :param project: project cn with prefix
    :param school: school name
    :return:
    """


    # Ensure prefix is given
    prefix = "p_"
    if school not in ["default-school", "global"]:
        prefix = f"p_{school}-"

    if not project.startswith(prefix):
        project = prefix + project

    try:
        project_details = lr.get(f'/projects/{project}', school=school, dict=False)
        if not project_details.cn:
            raise HTTPException(status_code=404, detail=f"Project {project} not found.")
        return project_details
    except Exception:
        raise HTTPException(status_code=404, detail=f"Project {project} not found.")

def get_printer_or_404(printer, school):
    try:
        printer_details = lr.get(f'/printers/{printer}', attributes=['cn'], school=school, dict=False)
        if not printer_details.cn:
            raise HTTPException(status_code=404, detail=f"Printer {printer} not found")
        return printer_details
    except Exception:
        raise HTTPException(status_code=404, detail=f"Printer {printer} not found")

