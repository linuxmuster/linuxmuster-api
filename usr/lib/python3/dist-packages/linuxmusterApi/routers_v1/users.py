from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

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

class SetFirstPassword(BaseModel):
    password: str
    set_current: bool = Field(default= False)

class SetCurrentPassword(BaseModel):
    password: str
    set_first: bool = Field(default= False)

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
def set_first_user_password(user: str, password: SetFirstPassword, auth: bool = Depends(PermissionChecker(["globaladministrator"]))):
    """
    Set first password from a specific user.
    """

    # TODO : paswword constraints ?
    lw.set(user, 'user', {'sophomorixFirstPassword': password.password})
    if password.set_current:
        try:
            user_manager.set_password(user, password.password)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Cannot set current password: {str(e)}")

@router.post("/{user}/set-current-password")
def set_current_user_password(user: str, password: SetCurrentPassword, auth: bool = Depends(PermissionChecker(["globaladministrator"]))):
    """
    Set current password from a specific user.
    """

    try:
        user_manager.set_password(user, password.password)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    if password.set_first:
        # TODO : paswword constraints ?
        lw.set(user, 'user', {'sophomorixFirstPassword': password.password})
