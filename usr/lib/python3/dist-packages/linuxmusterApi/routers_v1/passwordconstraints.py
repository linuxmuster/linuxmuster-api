import os
from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.lmnfile import LMNFile
from linuxmusterTools.passwords import CONFIG_PATH, PasswordRules
from .body_schemas import PasswordConstraintsConfig

router = APIRouter(
    prefix="/passwordconstraints",
    tags=["Password constraints"],
    responses={404: {"description": "Not found"}},
)


@router.get("/", name="Read password constraints")
def get_passwordconstraints(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Read the content of /etc/linuxmuster/tools/password_constraints.yml.

    Global administrators get the whole file (the global default rules and
    every school's override). School administrators only get the global
    default (for reference, read-only to them) and their own school's
    override, never another school's override.

    ### Access
    - school-administrators (own school only)
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Password constraints config, scoped by role
    :rtype: dict
    """


    if not os.path.isfile(CONFIG_PATH):
        return {}

    with LMNFile(str(CONFIG_PATH), 'r') as f:
        config = f.read() or {}

    if who.role == 'globaladministrator':
        return config

    return {
        "default": config.get("default", {}),
        "school": who.school,
        "override": config.get("schools", {}).get(who.school, {}),
    }


