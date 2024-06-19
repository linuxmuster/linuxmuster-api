from fastapi import HTTPException

from linuxmusterTools.ldapconnector import LMNLdapReader as lr


def get_user_or_404(user, school):
    user_details = lr.get(f'/users/{user}', school=school, dict=False)
    if not user_details.cn:
        raise HTTPException(status_code=404, detail=f"User {user} not found in ldap tree.")
    return user_details

def get_schoolclass_or_404(schoolclass):
    schoolclasses = [s['cn'] for s in lr.get('/schoolclasses', attributes=['cn'])]
    if schoolclass not in schoolclasses:
        raise HTTPException(status_code=404, detail=f"Schoolclass {schoolclass} not found")

def get_teacher_or_404(teacher):
    teachers = [s['cn'] for s in lr.get('/roles/teacher', attributes=['cn'])]
    if teacher not in teachers:
        raise HTTPException(status_code=404, detail=f"Teacher {teacher} not found")