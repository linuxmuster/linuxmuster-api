from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from security import PermissionChecker
from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.ldapconnector import LMNLdapWriter as lw
from linuxmusterTools.samba_util import UserManager

user_manager = UserManager()

router = APIRouter(
    prefix="/users",
    tags=["Users"],
    responses={404: {"description": "Not found"}},
)

class Password(BaseModel):
    password: str

@router.get("/")
def get_all_users(auth: bool = Depends(PermissionChecker("globaladministrator"))):
    """
    Get basic informations from all users
    """

    return lr.get('/users', attributes=['sn', 'givenName', 'sophomorixRole', 'sophomorixAdminClass'])

@router.get("/{user}")
def get_user(user: str, auth: bool = Depends(PermissionChecker(["globaladministrator"]))):
    """
    Get all details from a specific user.
    """

    return lr.get(f'/users/{user}')

@router.post("/{user}/set-first-password")
def set_first_user_password(user: str, password: Password, auth: bool = Depends(PermissionChecker(["globaladministrator"]))):
    """
    Set first password from a specific user.
    """

    # TODO : paswword constraints ?
    lw.set(user, 'user', {'sophomorixFirstPassword': password.password})

@router.post("/{user}/set-current-password")
def set_current_user_password(user: str, password: Password, auth: bool = Depends(PermissionChecker(["globaladministrator"]))):
    """
    Set current password from a specific user.
    """

    try:
        user_manager.set_password(user, password.password)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))