import os
from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.lmnfile import LMNFile
from linuxmusterTools.passwords import CONFIG_PATH
from .body_schemas import PasswordConstraintsConfig
from utils.checks import check_password_constraints_rules_or_400


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


@router.post("/", name="Write password constraints")
def post_passwordconstraints(content: PasswordConstraintsConfig, who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Write to /etc/linuxmuster/tools/password_constraints.yml.

    Global administrators can set the global default rules and any school's
    override in one call. School administrators are restricted to their own
    school: the "default" key must be omitted, "schools" may only contain
    their own school, and the rest of the file (default rules, other
    schools' overrides) is preserved untouched.

    ### Access
    - school-administrators (own school only)
    - global-administrators

    \f
    :param who: User requesting the write, read from API Token
    :type who: AuthenticatedUser
    :param content: Password constraints config to write, see PasswordConstraintsConfig
    :type content: PasswordConstraintsConfig
    :return: The config as written
    :rtype: dict
    """


    config = content.model_dump(exclude_none=True)

    if who.role != 'globaladministrator':
        if config.get("default"):
            raise HTTPException(
                status_code=403,
                detail="Only global administrators can set the global default rules")

        schools = config.get("schools", {})
        if set(schools) - {who.school}:
            raise HTTPException(
                status_code=403,
                detail="School administrators can only set their own school's rules")

        if not os.path.isfile(CONFIG_PATH):
            raise HTTPException(
                status_code=404,
                detail=f"{CONFIG_PATH} does not exist yet. A global-administrator must create it first."
            )

        with LMNFile(str(CONFIG_PATH), 'r') as f:
            config = f.read() or {}

        config.setdefault("schools", {})[who.school] = schools.get(who.school, {})

    for role, entries in config.get("default", {}).items():
        check_password_constraints_rules_or_400(role, entries)
    for school, roles in config.get("schools", {}).items():
        for role, entries in roles.items():
            check_password_constraints_rules_or_400(f"{school}/{role}", entries)

    try:
        with LMNFile(str(CONFIG_PATH), 'w') as f:
            return f.write(config)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error writing {CONFIG_PATH}: {str(e)}")
