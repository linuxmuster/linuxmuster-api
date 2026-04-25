import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from security import RoleChecker, AuthenticatedUser

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/vdi",
    tags=["VDI"],
    responses={404: {"description": "Not found"}},
)


def _get_vdi_context():
    """Lazy-load VdiContext from edulution-linbo-vdi package."""
    try:
        from edulution_linbo_vdi import VdiContext
        return VdiContext.from_config_file()
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="edulution-linbo-vdi is not installed on this server.",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to initialize VDI context: {exc}",
        )


def _get_vdi_groups():
    """Lazy-load VDI group discovery."""
    try:
        from edulution_linbo_vdi import device_store
        return device_store.get_vdi_groups()
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="edulution-linbo-vdi is not installed on this server.",
        )


class ConnectionRequest(BaseModel):
    """
    Request body for a VDI connection.
    """

    group: str
    user: str


# ---- Groups / Images ----

@router.get("/groups", name="List all VDI groups")
def get_vdi_groups(who: AuthenticatedUser = Depends(RoleChecker("GSTsPF"))):
    """
    ## List all available VDI groups (images).

    Returns each group with its activation status, OS type, and
    clone pool configuration (minimum, maximum, prestarted VMs).

    ### Access
    - all authenticated users

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of VDI groups with configuration
    :rtype: dict
    """

    vdi_groups = _get_vdi_groups()
    result = []
    for name, data in vdi_groups["groups"].items():
        activated = data.get("activated", False)
        if isinstance(activated, str):
            activated = activated.lower() in ("yes", "true", "1")
        result.append({
            "name": name,
            "activated": activated,
            "ostype": data.get("ostype", ""),
            "cores": data.get("cores", 0),
            "memory": data.get("memory", 0),
            "minimum_vms": data.get("minimum_vms", 0),
            "maximum_vms": data.get("maximum_vms", 0),
            "prestarted_vms": data.get("prestarted_vms", 0),
        })
    return result


# ---- Clone status ----

@router.get("/clones", name="Get clone status for all groups")
def get_clone_status(who: AuthenticatedUser = Depends(RoleChecker("ALL"))):
    """
    ## Get the clone status for all VDI groups.

    Returns the number of existing, available, building, and failed
    clones per group.

    ### Access
    - all authenticated users

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Clone status per group
    :rtype: dict
    """

    ctx = _get_vdi_context()
    from edulution_linbo_vdi.clone import CloneManager
    clone_mgr = CloneManager(ctx)

    try:
        return clone_mgr.get_all_states()
    except Exception as exc:
        logger.error("Error getting clone states: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/clones/{group}", name="Get clone status for a specific group")
def get_clone_status_by_group(group: str, who: AuthenticatedUser = Depends(RoleChecker("ALL"))):
    """
    ## Get the clone status for a specific VDI group.

    Returns detailed information about each clone VM including
    build state, connection status, and summary counters.

    ### Access
    - all authenticated users

    \f
    :param group: Name of the VDI group
    :type group: str
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Clone status details
    :rtype: dict
    """

    vdi_groups = _get_vdi_groups()
    if group not in vdi_groups["groups"]:
        raise HTTPException(status_code=404, detail=f"VDI group '{group}' not found")

    ctx = _get_vdi_context()
    from edulution_linbo_vdi.clone import CloneManager
    clone_mgr = CloneManager(ctx)

    try:
        group_data = vdi_groups["groups"][group]
        return clone_mgr.get_states(group_data, group)
    except Exception as exc:
        logger.error("Error getting clone states for %s: %s", group, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---- Master status ----

@router.get("/masters", name="Get master status for all groups")
def get_master_status(who: AuthenticatedUser = Depends(RoleChecker("GS"))):
    """
    ## Get the master status for all VDI groups.

    Returns the build state and image information for each master VM.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Master status per group
    :rtype: dict
    """

    ctx = _get_vdi_context()
    from edulution_linbo_vdi.master import MasterManager
    master_mgr = MasterManager(ctx)

    try:
        return master_mgr.get_all_states()
    except Exception as exc:
        logger.error("Error getting master states: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---- Connection request ----

@router.post("/connection", name="Request a VDI connection")
def request_connection(data: ConnectionRequest, who: AuthenticatedUser = Depends(RoleChecker("GSTsPF"))):
    """
    ## Request a SPICE connection to a VDI desktop.

    Assigns an available clone VM to the requesting user and returns
    the VM details and SPICE configuration for connecting.

    The broker prefers:
    1. A VM the user was recently assigned to
    2. An unused VM
    3. A VM whose previous assignment has timed out

    ### Access
    - all authenticated users

    \f
    :param data: Connection request with group and user
    :type data: ConnectionRequest
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: VM info with IP and SPICE config
    :rtype: dict
    """

    vdi_groups = _get_vdi_groups()
    if data.group not in vdi_groups["groups"]:
        raise HTTPException(status_code=404, detail=f"VDI group '{data.group}' not found")

    ctx = _get_vdi_context()
    from edulution_linbo_vdi.broker import ConnectionBroker
    from edulution_linbo_vdi.clone import CloneManager
    from edulution_linbo_vdi.exceptions import NoDesktopAvailableError

    broker = ConnectionBroker(ctx)
    clone_mgr = CloneManager(ctx)

    try:
        conn = broker.get_connection(data.group, data.user)
    except NoDesktopAvailableError:
        raise HTTPException(status_code=503, detail=f"No desktop available for user '{data.user}' in group '{data.group}'")
    except Exception as exc:
        logger.error("Error getting connection for %s: %s", data.user, exc)
        raise HTTPException(status_code=500, detail=str(exc))

    # Find the assigned VM to return its details
    group_data = vdi_groups["groups"][data.group]
    vm_states = clone_mgr.get_states(group_data, data.group)
    vm_info = {}
    if vm_states:
        for vmid, info in vm_states.items():
            if vmid == "summary" or not isinstance(info, dict):
                continue
            if info.get("lastConnectionRequestUser") == data.user:
                vm_info = {
                    "vmid": vmid,
                    "name": info.get("name", ""),
                    "ip": info.get("ip", ""),
                    "status": info.get("status", ""),
                    "group": data.group,
                }
                break

    return {
        "vm": vm_info,
        "spice": conn,
    }
