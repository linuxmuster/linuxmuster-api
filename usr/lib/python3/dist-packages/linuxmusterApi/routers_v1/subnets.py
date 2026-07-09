import os
from fastapi import APIRouter, Depends, HTTPException

from security import RoleChecker, AuthenticatedUser
from linuxmusterTools.lmnfile import LMNFile
from linuxmusterTools.subnets import Subnets, import_subnets, SUBNETS_PATH
from .body_schemas import MgmtList

router = APIRouter(
    prefix="/subnets",
    tags=["Subnets"],
    responses={404: {"description": "Not found"}},
)

@router.get("/list", name="List all subnets")
def get_all_subnets(who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## List the content of /etc/linuxmuster/subnets.csv.

    Every line of the CSV file is returned as a dict, including comment lines
    (their *network* field then starts with a '#'), so that the list can be
    edited and posted back without losing comments.

    Subnets are not bound to a school: there is a single, server wide file.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of all subnets (list of dict, one dict per line in CSV)
    :rtype: list
    """


    if not os.path.isfile(SUBNETS_PATH):
        return []

    with LMNFile(SUBNETS_PATH, 'r') as f:
        return f.read()

@router.post("/list", name="Write content of subnets.csv")
def post_subnets_list_content(content: MgmtList, who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Write the content of /etc/linuxmuster/subnets.csv.

    This will overwrite the content of the CSV file, but LMNFile automatically
    makes a backup of the old CSV file. The changes only take effect on the
    running system after linuxmuster-import-subnets has been run (see the
    import-subnets endpoint).

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :param content: Content of the CSV, see MgmtList attributes
    :type content: MgmtList
    :return: Content of the csv file (list of dict, one dict per line in CSV)
    :rtype: list
    """


    try:
        with LMNFile(SUBNETS_PATH, 'w') as subnets_file:
            return subnets_file.write(content.data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error writing {SUBNETS_PATH}: {str(e)}")

@router.get("/check", name="Validate subnets.csv")
def check_subnets(who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Validate the content of /etc/linuxmuster/subnets.csv.

    Checks that networks are valid CIDR, that router/range/server addresses are
    valid IPs belonging to their network and that the setup flag is valid.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: {"valid": bool, "report": list of error messages}
    :rtype: dict
    """


    report = Subnets().check_conf()
    return {"valid": report is False, "report": report or []}

@router.get("/list/import-subnets", name="Run linuxmuster-import-subnets")
def do_import_subnets(who: AuthenticatedUser = Depends(RoleChecker("G"))):
    """
    ## Run linuxmuster-import-subnets.

    This regenerates the DHCP, ntp and netplan configuration from
    /etc/linuxmuster/subnets.csv and restarts the affected services.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Return code and output of linuxmuster-import-subnets
    :rtype: dict
    """


    return import_subnets()
