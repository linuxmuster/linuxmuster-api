from fastapi import HTTPException

from linuxmusterTools.ldapconnector import LMNLdapReader as lr


def get_user_or_404(user, school):
    try:
        user_details = lr.get(f'/users/{user}', school=school, dict=False)
        if not user_details.cn:
            raise HTTPException(status_code=404, detail=f"User {user} not found in ldap tree.")
        return user_details
    except Exception:
        raise HTTPException(status_code=404,
                            detail=f"User {user} not found in ldap tree.")


def get_schoolclass_or_404(schoolclass, school):
    try:
        schoolclass_data = lr.get(f'/schoolclasses/{schoolclass}', school=school)
        if not schoolclass_data:
            raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found")
        return schoolclass_data
    except Exception:
        raise HTTPException(status_code=404,
                            detail=f"Schoolclass {schoolclass} not found")


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
        raise HTTPException(status_code=404,
                            detail=f"Project {project} not found.")


def get_printer_or_404(printer, school):
    try:
        printer_details = lr.get(f'/printers/{printer}', attributes=['cn'], school=school, dict=False)
        if not printer_details.cn:
            raise HTTPException(status_code=404, detail=f"Printer {printer} not found")
        return printer_details
    except Exception:
        raise HTTPException(status_code=404,
                            detail=f"Printer {printer} not found")

