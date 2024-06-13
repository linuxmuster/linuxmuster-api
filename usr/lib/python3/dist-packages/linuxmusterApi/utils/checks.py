from fastapi import HTTPException

from linuxmusterTools.ldapconnector import LMNLdapReader as lr


def get_user_or_404(user, school):
    user_details = lr.get(f'/users/{user}', school=school, dict=False)
    if not user_details.cn:
        raise HTTPException(status_code=404, detail=f"User {user} not found in ldap tree.")
    return user_details