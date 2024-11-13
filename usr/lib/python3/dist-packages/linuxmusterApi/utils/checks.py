from fastapi import HTTPException

from linuxmusterTools.ldapconnector import LMNLdapReader as lr


def get_user_or_404(user, school):
    user_details = lr.get(f'/users/{user}', school=school, dict=False)
    if not user_details.cn:
        raise HTTPException(status_code=404, detail=f"User {user} not found in ldap tree.")
    return user_details

def get_schoolclass_or_404(schoolclass, school):
    schoolclass = lr.get(f'/schoolclasses/{schoolclass}', school=school)
    if not schoolclass:
        raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found")
    return schoolclass

def get_teacher_or_404(teacher, school):
    user = lr.get(f'/users/{teacher}', school=school)
    if user.get('sophomorixAdminClass', '') != "teachers":
        raise HTTPException(status_code=404, detail=f"Teacher {teacher} not found")
    return user

def get_project_or_404(project, school):
    project_details = lr.get(f'/projects/{project}', school=school, dict=False)
    if not project_details.cn:
        raise HTTPException(status_code=404, detail=f"Project {project} not found.")
    return project_details

def get_printer_or_404(printer, school):
    printer_details = lr.get(f'/printers/{printer}', attributes=['cn'], school=school, dict=False)
    if not printer_details.cn:
        raise HTTPException(status_code=404, detail=f"Printer {printer} not found")
    return printer_details
