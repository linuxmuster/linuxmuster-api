"""REST endpoints for linbo-remote: run commands, list running sessions,
probe a host's boot state.

The router only translates HTTP requests and errors. Building/running the
command, listing tmux sessions and probing ports stay in
linuxmusterTools.linbo (LinboRemote, list_running_sessions, classify_host).
"""

from fastapi import APIRouter, Depends, HTTPException

from linuxmusterTools.devices import Devices
from linuxmusterTools.linbo import (
    LinboRemote,
    LinboRemoteParameterError,
    list_running_sessions,
)
from linuxmusterTools.linbo.host_status import classify_host
from security import AuthenticatedUser, RoleChecker
from utils.checks import require_school
from .body_schemas import LinboRemoteRunBody


router = APIRouter(
    prefix="/linbo/sync",
    tags=["LINBO Sync"],
    responses={404: {"description": "Not found"}},
)

# Mirrors the cap already used for /linbo/wol and /linbo/hosts/scan.
MAX_CLIENTS_PER_RUN = 500


@router.post("/run", name="Build and run a linbo-remote command")
@require_school
def run_linbo_remote(
    body: LinboRemoteRunBody,
    school: str = "",
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Build and run a linbo-remote command against a group, room or hosts.

    A school-administrator can only target their own school; a
    global-administrator must specify one explicitly.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param body: Target (group/room/clients), command and options
    :param school: School to target (required for global-administrators)
    """


    active_school = school if school else who.school

    if len(body.clients) > MAX_CLIENTS_PER_RUN:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_CLIENTS_PER_RUN} clients per request")

    remote = LinboRemote(
        cmd=body.cmd,
        group=body.group,
        room=body.room,
        clients=body.clients,
        wait=body.wait,
        wol=body.wol,
        disable_gui=body.disable_gui,
        broadcast=body.broadcast,
        bypass=body.bypass,
        onboot=body.onboot,
        school=None if active_school == "default-school" else active_school,
    )

    try:
        return remote.run()
    except LinboRemoteParameterError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@router.get("/sessions", name="List running linbo-remote sessions")
def get_running_sessions(
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## List the linbo-remote tmux sessions currently running on the server.

    A global-administrator sees every session. A school-administrator only
    sees sessions for hosts belonging to their own school.

    ### Access
    - global-administrators
    - school-administrators

    \f
    """


    sessions = list_running_sessions()

    if who.school == 'global':
        return {"sessions": sessions}

    known_hostnames = {
        f'{who.school}-{device["hostname"]}' if who.school != 'default-school' else device['hostname']
        for device in Devices(school=who.school).devices
    }
    return {"sessions": [s for s in sessions if s['hostname'] in known_hostnames]}


@router.get("/hosts/{hostname}/status", name="Probe a host's boot state")
def get_host_status(
    hostname: str,
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Probe a host on ports 2222/22/135 and report its boot state.

    One of 'Off', 'Linbo', 'OS Linux', 'OS Windows', 'OS Unknown'. A
    school-administrator can only probe hosts belonging to their own school.

    ### Access
    - global-administrators
    - school-administrators

    \f
    :param hostname: Hostname or IP to probe
    """


    if who.school != 'global':
        known_hostnames = {
            f'{who.school}-{device["hostname"]}' if who.school != 'default-school' else device['hostname']
            for device in Devices(school=who.school).devices
        }
        if hostname not in known_hostnames:
            raise HTTPException(status_code=404, detail=f"Host {hostname} not found")

    return {"hostname": hostname, "status": classify_host(hostname)}
