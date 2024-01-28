from fastapi import APIRouter, Depends, HTTPException

from security import PermissionChecker
from linuxmusterTools.ldapconnector import LMNLdapReader as lr


router = APIRouter(
    prefix="/query",
    tags=["Query"],
    responses={404: {"description": "Not found"}},
)

@router.get("/{school}/{sam}")
def query_user(school: str='default-school', sam: str='', auth: bool = Depends(PermissionChecker("globaladministrator"))):

    if school == 'global':
        return lr.get(f'/search/{sam}')

    return lr.get(f'/search/{sam}', school=school)
