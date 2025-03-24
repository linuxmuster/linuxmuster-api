import subprocess
from fastapi import APIRouter, Depends, HTTPException, Request

from security import RoleChecker, AuthenticatedUser


router = APIRouter(
    prefix="/server",
    tags=["Server"],
    responses={404: {"description": "Not found"}},
)

@router.get("/lmnversion", name="List Linuxmuster.net's packages installed")
def get_lmn_version(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## List all schools.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Packages installed and their versions
    :rtype: dict
    """


    packages = subprocess.check_output("dpkg -l | grep 'linuxmuster-\|sophomorix' | awk 'BEGIN {OFS=\"=\";} {print $2,$3}'", shell=True).decode().split()
    return dict([package.split('=') for package in packages])