"""
LINBO sync endpoints — thin REST layer over linuxmusterTools.linbo.

All business logic lives in linuxmusterTools.linbo modules.
This router only handles HTTP concerns (auth, validation, responses).
"""

import os.path
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request as FARequest
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse, StreamingResponse, Response

from security import AuthenticatedUser, RoleChecker
from utils.checks import (
    check_linbo_backup_date_or_404,
    check_linbo_image_group_or_404,
    check_new_linbo_image_name_or_409,
    check_valid_school_or_404,
    require_school,
    run_linbo_image_operation,
)
from .body_schemas import (
    LinboBatchMacs,
    LinboHostScanBody,
    LinboImageExtrasBody,
    LinboImageNameBody,
    LinboWolBody,
    StartConfRawBody,
)


from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.devices import Devices

from linuxmusterTools.linbo import *
from linuxmusterTools.lmnfile import LMNFile
from linuxmusterTools.common.checks import NameChecker


name_checker = NameChecker()

router = APIRouter(
    prefix="/linbo",
    tags=["LINBO"],
    responses={404: {"description": "Not found"}},
)

# --- Paths ---

LINBO_DIR = Path("/srv/linbo")
IMAGES_DIR = LINBO_DIR / "images"

# A scan runs until every host has answered or timed out, so the host count is
# capped and the probes run wider than the library default of 20.
MAX_HOSTS_PER_SCAN = 500
SCAN_CONCURRENCY = 100


def _parse_list_query(values: list[str], param_name: str, max_items: int) -> list[str]:
    """Accept repeated and comma-separated query params while preserving order."""
    items: list[str] = []
    for value in values:
        items.extend(part.strip() for part in value.split(","))

    filtered = [item for item in items if item]
    if not filtered:
        raise HTTPException(status_code=400, detail=f"At least one {param_name} value is required")
    if len(filtered) > max_items:
        raise HTTPException(status_code=400, detail=f"Maximum {max_items} {param_name} values per request")
    return filtered


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/server-info", name="LMN server network info for auto-setup")
def get_server_info(
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Server network configuration for auto-setup.

    ### Access
    - global-administrators

    \f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    """


    try:
        with LMNFile('/var/lib/linuxmuster/setup.ini', 'r') as setup:
            data = setup.read()
            ini = data.get('setup', {}) if isinstance(data, dict) else {}
    except OSError:
        raise HTTPException(status_code=500, detail="setup.ini not found or unreadable")

    if not ini:
        raise HTTPException(status_code=500, detail="setup.ini empty or invalid")

    schools = lr.getval('/schools', 'ou')

    return {
        "serverip": ini.get("serverip", ""),
        "servername": ini.get("servername", ""),
        "domainname": ini.get("domainname", ""),
        "realm": ini.get("realm", ""),
        "sambadomain": ini.get("sambadomain", ""),
        "basedn": ini.get("basedn", ""),
        "gateway": ini.get("gateway", ""),
        "firewallip": ini.get("firewallip", ""),
        "network": ini.get("network", ""),
        "netmask": ini.get("netmask", ""),
        "bitmask": ini.get("bitmask", ""),
        "broadcast": ini.get("broadcast", ""),
        "schools": schools,
    }


@router.get("/health", name="LINBO subsystem health check")
def linbo_health(
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## LINBO subsystem health check.

    ### Access
    - global-administrators

    \f
    :param school: School name (default: default-school)
    :type school: str
    """


    check_valid_school_or_404(school)
    csv_path_exists = os.path.isfile(Devices(school).path)
    config_ids = LinboConfigManager().group_ids
    grub_reader = LinboGrubReader()

    return {
        "status": "ok" if csv_path_exists and LINBO_DIR.is_dir() else "degraded",
        "devicesCSV": csv_path_exists,
        "linboDir": LINBO_DIR.is_dir(),
        "startConfs": len(config_ids),
        "grubConfigs": len(grub_reader.list_grub_cfg_ids()),
    }


@router.get("/changes", name="Delta feed for LINBO sync")
@require_school
def get_changes(
    since: str = "0",
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Get changes since last sync (delta feed).

    ### Access
    - global-administrators
    - school-administrators (scoped to their own school)

    \f
    :param since: Cursor from previous sync (unix timestamp), or '0' for full snapshot
    :param school: School name (default: default-school)
    """


    check_valid_school_or_404(school)
    tracker = LinboChangeTracker(school=school)
    return tracker.get_changes(since_cursor=since)


@router.post("/hosts/query", name="Query hosts by MAC address list")
@require_school
def query_hosts(
    body: LinboBatchMacs,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Get host records for a list of MAC addresses.

    ### Access
    - global-administrators
    - school-administrators (scoped to their own school)

    \f
    :param body: List of MAC addresses to look up
    :param school: School name (default: default-school)
    """


    check_valid_school_or_404(school)

    if len(body.macs) > 500:
        raise HTTPException(status_code=400, detail="Maximum 500 MACs per request")

    hosts = Devices(school=school).get_hosts_by_macs(body.macs)

    if not hosts:
        raise HTTPException(status_code=404, detail="No hosts found for given MACs")

    return {"hosts": hosts}


# TODO: startconfs/configs (this section) stay G-only on purpose — group_id has
# no school ownership anywhere in linuxmusterTools.linbo (raw, flat, global
# /srv/linbo/start.conf.<id>), same gap as the legacy lmn_linbo4 plugin. Opening
# to school-admins needs real per-school ownership in lmntools first, not a
# quick RoleChecker flip.
@router.get("/linbo-groups", name="List LINBO hardware group IDs")
def get_linbo_groups(
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## List the hardware group IDs with an existing start.conf file.

    ### Access
    - global-administrators
    """


    return {"groups": LinboConfigManager().group_ids}

@router.get("/startconfs", name="Get start.conf files by ID")
def get_startconfs(
    id: list[str] = Query(..., alias="id", description="One or more start.conf IDs"),
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Get start.conf file contents for a list of group IDs.

    ### Access
    - global-administrators

    \f
    :param id: List of start.conf group IDs, either repeated or comma-separated
    :param school: School name (default: default-school)
    """


    check_valid_school_or_404(school)
    ids = _parse_list_query(id, "id", 100)

    raw_startconfs = LinboConfigManager().load_raw_startconfs(ids)

    return {"startConfs": raw_startconfs}

# TODO: HTTP verb inconsistency — this is an upsert (create-or-update), compare with
# save_image_extras (full overwrite, same kind of operation) which uses PUT instead
@router.post("/startconfs/{group_id}", name="Create or update a start.conf file")
def write_startconf(
    group_id: str,
    body: StartConfRawBody,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Create or update a start.conf file for a LINBO group.

    The payload is the raw file content (comments and formatting preserved
    verbatim), matching the shape returned by GET /startconfs. The file is
    created if it doesn't exist yet.

    ### Access
    - global-administrators

    \f
    :param group_id: LINBO group id (the `<id>` in start.conf.<id>)
    :param body: Raw start.conf content
    :param school: School name (default: default-school)
    """


    check_valid_school_or_404(school)

    try:
        LinboConfigManager().write_raw_startconf(group_id, body.content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"id": group_id, "status": "ok"}


@router.delete("/startconfs/{group_id}", name="Delete a start.conf file")
def delete_startconf(
    group_id: str,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Delete a start.conf file and its associated GRUB config.

    Same behaviour as the legacy webui `lmn_linbo4` plugin.

    ### Access
    - global-administrators

    \f
    :param group_id: LINBO group id (the `<id>` in start.conf.<id>)
    :param school: School name (default: default-school)
    """


    check_valid_school_or_404(school)

    try:
        LinboConfigManager().delete_startconf(group_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {"id": group_id, "status": "deleted"}


@router.get("/configs", name="Get GRUB configs by ID")
def get_configs(
    id: list[str] = Query(..., alias="id", description="One or more GRUB config IDs"),
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Get GRUB configuration files for a list of group IDs.

    ### Access
    - global-administrators

    \f
    :param id: List of GRUB config group IDs, either repeated or comma-separated
    :param school: School name (default: default-school)
    """


    check_valid_school_or_404(school)
    ids = _parse_list_query(id, "id", 100)

    grub_reader = LinboGrubReader()
    results = grub_reader.get_configs_by_ids(ids)

    if not results:
        raise HTTPException(status_code=404, detail="No GRUB configs found for given IDs")

    return {"configs": results}


@router.get(
    "/dhcp/export/dnsmasq-proxy",
    name="DHCP export for dnsmasq proxy mode",
    response_class=PlainTextResponse,
)
@require_school
def dhcp_export_dnsmasq(
    request: FARequest,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Generate dnsmasq proxy-DHCP configuration.

    ### Access
    - global-administrators
    - school-administrators (scoped to their own school)

    \f
    :param school: School name (default: default-school)
    """


    check_valid_school_or_404(school)

    devices_mgr = Devices(school=school)
    try:
        devices = devices_mgr.devices
        csv_mtime = devices_mgr.csv_mtime
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="devices.csv not found")

    if not devices:
        raise HTTPException(status_code=404, detail="devices.csv empty")

    exporter = LinboDhcpExporter()
    content = exporter.generate_dnsmasq_proxy(devices)
    etag = exporter.content_etag(content)

    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match.strip('"') == etag:
        return PlainTextResponse(content="", status_code=304, headers={"ETag": f'"{etag}"'})

    headers = {"ETag": f'"{etag}"'}
    if csv_mtime:
        headers["Last-Modified"] = csv_mtime.strftime("%a, %d %b %Y %H:%M:%S GMT")

    return PlainTextResponse(content=content, headers=headers)


@router.get("/grub-configs", name="All GRUB configs for a school")
@require_school
def get_all_grub_configs(
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Export all GRUB config files for a school.

    ### Access
    - global-administrators
    - school-administrators (scoped to their own school)

    \f
    :param school: School name (default: default-school)
    """


    check_valid_school_or_404(school)

    try:
        school_groups = Devices(school=school).groups
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"School '{school}' not found")

    grub_reader = LinboGrubReader()
    configs = grub_reader.get_all_grub_configs(school_groups=school_groups)

    return {"configs": configs, "school": school, "total": len(configs)}


@router.get("/dhcp/export/isc-dhcp", name="ISC DHCP export for school")
@require_school
def dhcp_export_isc(
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Export ISC DHCP configuration for a school.

    ### Access
    - global-administrators
    - school-administrators (scoped to their own school)

    \f
    :param school: School name (default: default-school)
    """


    check_valid_school_or_404(school)

    exporter = LinboDhcpExporter()
    return exporter.get_isc_dhcp(school)


# ── Host state ─────────────────────────────────────────────────────


@router.post("/hosts/scan", name="Probe hosts for online status")
async def probe_hosts(
    body: LinboHostScanBody,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Probe hosts over TCP and report which ones are online.

    An empty MAC list scans every client of the school.

    ### Access
    - global-administrators
    - school-administrators (scoped to their own school)

    \f
    :param body: MAC addresses to probe, empty for all clients of the school
    :param school: School name (default: default-school)
    """

    # probe_hosts is async, so it can't use @require_school (sync-only): guard
    # inline instead. `who` is None in the direct-call unit tests below, which
    # predate school-admin access and never exercised permissions here.
    if who is not None and who.school not in ('global', school):
        raise HTTPException(status_code=403, detail="school-administrators can only operate on their own school.")

    check_valid_school_or_404(school)

    if len(body.macs) > MAX_HOSTS_PER_SCAN:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_HOSTS_PER_SCAN} MACs per request")

    devices_mgr = Devices(school=school)
    hosts = devices_mgr.get_hosts_by_macs(body.macs) if body.macs else devices_mgr.get_clients()

    if not hosts:
        raise HTTPException(status_code=404, detail="No hosts found")

    # The cap above only covers an explicit list; an empty one resolves to every
    # client of the school, which is unbounded.
    if len(hosts) > MAX_HOSTS_PER_SCAN:
        raise HTTPException(
            status_code=400,
            detail=f"School {school} has {len(hosts)} clients, more than the {MAX_HOSTS_PER_SCAN} a single scan allows",
        )

    return {
        "hosts": await scan_hosts(hosts, concurrency=SCAN_CONCURRENCY),
        "scannedAt": datetime.now(timezone.utc).isoformat(),
    }


# TODO: wol stays G-only for now, but unlike startconfs/images this one is a
# cheap fix whenever it's picked up — no lmntools change needed, just check
# each MAC against Devices(who.school) before opening to school-admins, same
# pattern already used for /hosts/image-status.
@router.post("/wol", name="Wake hosts with a magic packet")
def wake_hosts(
    body: LinboWolBody,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Send Wake-on-LAN magic packets to a list of MAC addresses.

    ### Access
    - global-administrators

    \f
    :param body: MAC addresses to wake, with broadcast address, port and packet count
    """


    if not body.macs:
        raise HTTPException(status_code=400, detail="At least one MAC address is required")

    if len(body.macs) > MAX_HOSTS_PER_SCAN:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_HOSTS_PER_SCAN} MACs per request")

    return send_wol_bulk(
        body.macs,
        broadcast=str(body.broadcast) if body.broadcast else None,
        port=body.port,
        count=body.count,
    )


@router.get("/hosts/image-status", name="Last sync per host from the boot logs")
def hosts_image_status(
    who: AuthenticatedUser = Depends(RoleChecker("GS")),
):
    """
    ## Report the last applied image per host, read from the LINBO boot logs.

    Hosts that never reported carry no entry. A global-administrator sees
    every host; a school-administrator only sees hosts belonging to their
    own school.

    ### Access
    - global-administrators
    - school-administrators

    \f
    """


    hosts = get_host_image_status()

    if who.school == 'global':
        return {"hosts": hosts, "total": len(hosts)}

    prefix = f'{who.school}-' if who.school != 'default-school' else ''
    known_hostnames = {
        f'{prefix}{device["hostname"]}'
        for device in Devices(school=who.school).devices
    }
    hosts = {hostname: status for hostname, status in hosts.items() if hostname in known_hostnames}
    return {"hosts": hosts, "total": len(hosts)}


# TODO: boot-logs (this section) stays G-only for now, but like wol it's a
# cheap fix later — filenames are "<hostname>.log", so hostname just needs
# checking against Devices(who.school), same pattern as /hosts/image-status.
# ── Boot logs ──────────────────────────────────────────────────────


@router.get("/boot-logs", name="List LINBO client boot logs")
def list_boot_logs(
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## List the client boot logs, newest first.

    ### Access
    - global-administrators

    \f
    """


    logs = LinboBootLogs().list_logs()
    return {"logs": logs, "total": len(logs)}


@router.get(
    "/boot-logs/{filename}",
    name="Read a LINBO client boot log",
    response_class=PlainTextResponse,
)
def read_boot_log(
    filename: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Read one boot log.

    ### Access
    - global-administrators

    \f
    :param filename: Name of the log file
    """


    try:
        content = LinboBootLogs().read_log(filename)
    except ValueError as e:
        # read_log raises ValueError for an unsafe name and for a log over its size
        # limit. Only the first is the caller's fault; a log the list endpoint just
        # advertised is not a bad request.
        status_code = 413 if "too large" in str(e).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(e))

    if content is None:
        raise HTTPException(status_code=404, detail=f"Boot log {filename} not found")

    return PlainTextResponse(content=content)


@router.delete("/boot-logs/{filename}", name="Delete a LINBO client boot log")
def delete_boot_log(
    filename: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Delete one boot log.

    ### Access
    - global-administrators

    \f
    :param filename: Name of the log file
    """


    try:
        deleted = LinboBootLogs().delete_log(filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FileNotFoundError:
        # logrotate rotates and compresses this directory, so a log can disappear
        # between delete_log's is_file() and its unlink(). Same answer as a log that
        # was never there. FileNotFoundError is an OSError, so it is caught first.
        raise HTTPException(status_code=404, detail=f"Boot log {filename} not found")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Could not delete boot log {filename}: {e}")

    if not deleted:
        raise HTTPException(status_code=404, detail=f"Boot log {filename} not found")

    return {"filename": filename, "status": "deleted"}


# TODO: every images/* route (this section onward) stays G-only on purpose —
# LinboImageManager/LinboImageGroup have no school concept at all, images are
# one shared pool at /srv/linbo/images for the whole server, same as the
# legacy lmn_linbo4 plugin. Opening to school-admins would need a real school
# ownership scheme in lmntools first (new feature, not a bugfix).
# ── Image Manifest ─────────────────────────────────────────────────


@router.get("/images/manifest", name="Image manifest for sync")
def get_image_manifest(
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## List all LINBO images with metadata.

    ### Access
    - global-administrators

    \f
    """


    linbo_mgr = LinboImageManager()
    images = linbo_mgr.get_images_infos()
    return {
        "images": images,
        "total": len(images),
        "scannedAt": datetime.now(timezone.utc).isoformat(),
    }


# ── Image Download ─────────────────────────────────────────────────


@router.get("/images/download/{image_name}/{filename}", name="Download image or extra_file")
@router.head("/images/download/{image_name}/{filename}", name="HEAD image or extra_file")
def download_image_file(
    image_name: str,
    filename: str,
    request: FARequest,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Download an image or extra_file with HTTP Range support.

    ### Access
    - global-administrators

    \f
    """


    try:
        file_path = resolve_image_file(IMAGES_DIR, image_name, filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

    info = get_image_file_info(file_path)
    file_size = info["size"]

    headers = {
        "Content-Length": str(file_size),
        "ETag": f'"{info["etag"]}"',
        "Last-Modified": info["last_modified"],
        "Accept-Ranges": "bytes",
    }

    if request.method == "HEAD":
        return Response(content=b"", headers=headers)

    range_header = request.headers.get("range")
    if range_header:
        try:
            range_spec = range_header.replace("bytes=", "")
            start_str, end_str = range_spec.split("-")
            start = int(start_str) if start_str else 0
            end = int(end_str) if end_str else file_size - 1
            end = min(end, file_size - 1)

            if start >= file_size or start > end:
                raise HTTPException(
                    status_code=416,
                    detail=f"Range not satisfiable (file size: {file_size})",
                    headers={"Content-Range": f"bytes */{file_size}"},
                )

            content_length = end - start + 1

            def range_iterator():
                with open(file_path, "rb") as f:
                    f.seek(start)
                    remaining = content_length
                    while remaining > 0:
                        chunk_size = min(65536, remaining)
                        data = f.read(chunk_size)
                        if not data:
                            break
                        remaining -= len(data)
                        yield data

            return StreamingResponse(
                range_iterator(),
                status_code=206,
                headers={
                    "Content-Range": f"bytes {start}-{end}/{file_size}",
                    "Content-Length": str(content_length),
                    "ETag": f'"{info["etag"]}"',
                    "Accept-Ranges": "bytes",
                },
                media_type="application/octet-stream",
            )
        except (ValueError, IndexError):
            raise HTTPException(status_code=416, detail="Invalid Range header")

    def file_iterator():
        with open(file_path, "rb") as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                yield data

    return StreamingResponse(file_iterator(), headers=headers, media_type="application/octet-stream")


# ── Image Upload ───────────────────────────────────────────────────


@router.put("/images/upload/{image_name}/{filename}", name="Upload image or extra_file (chunked)")
async def upload_image_file(
    image_name: str, filename: str, request: FARequest,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Upload an image or extra_file with Content-Range support.

    ### Access
    - global-administrators

    \f
    """


    try:
        # TODO: should test if the image really exists, and not only path
        # transversality and string validation
        name_checker.check_linbo_image_name(image_name)
        name_checker.check_linbo_image_name(filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    offset = None
    content_range = request.headers.get("content-range")
    if content_range:
        try:
            range_spec = content_range.replace("bytes ", "")
            range_part, _ = range_spec.split("/")
            start_str, _ = range_part.split("-")
            offset = int(start_str)
        except (ValueError, IndexError):
            raise HTTPException(status_code=400, detail="Invalid Content-Range")

    body = await request.body()
    try:
        return await run_in_threadpool(
            receive_upload_chunk, IMAGES_DIR, image_name, filename, body, offset
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/images/upload/{image_name}/{filename}/status", name="Check upload status for resume")
def upload_status_endpoint(
    image_name: str, filename: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Check how many bytes have been received for a chunked upload.

    ### Access
    - global-administrators

    \f
    """


    try:
        return get_upload_status(IMAGES_DIR, image_name, filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/images/upload/{image_name}/complete", name="Finalize image upload")
def finalize_upload_endpoint(
    image_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Move uploaded files from staging to final images directory.

    If the target directory already contains image files, they are backed up
    to a timestamped subdirectory before being replaced.

    ### Access
    - global-administrators

    \f
    """


    try:
        return finalize_upload(IMAGES_DIR, image_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/images/upload/{image_name}", name="Cancel/cleanup upload")
def cancel_upload_endpoint(
    image_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Clean up staged upload files on cancel or failure.

    ### Access
    - global-administrators

    \f
    """


    try:
        return cancel_upload(IMAGES_DIR, image_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Image Management ───────────────────────────────────────────────


@router.get("/images", name="List LINBO images with backups and sidecars")
def list_images(
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## List every LINBO image with its sidecars, backups and differential image.

    `/images/manifest` reports what the sync clients need. This reports what an
    image management UI needs: the `reg`, `postsync` and `prestart` contents and
    the backup list, which the manifest leaves out.

    ### Access
    - global-administrators

    \f
    """


    manager = LinboImageManager()
    images = [group.to_dict() for group in manager.groups.values()]
    return {"images": images, "total": len(images)}


@router.get("/images/{image_name}/backups", name="List an image's backups")
def list_image_backups(
    image_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## List the backups of one LINBO image.

    Keys are the `YYYYMMDDhhmm` timestamps the other backup endpoints take.

    ### Access
    - global-administrators

    \f
    :param image_name: Name of the LINBO image
    """


    group = check_linbo_image_group_or_404(LinboImageManager(), image_name)
    backups = {
        backup.timestamp: backup.to_dict()
        for backup in group.backups.values()
    }
    return {"image": image_name, "backups": backups, "total": len(backups)}


@router.delete("/images/{image_name}", name="Delete a LINBO image")
def delete_image(
    image_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Delete a LINBO image with its backups, differential image and sidecars.

    ### Access
    - global-administrators

    \f
    :param image_name: Name of the LINBO image
    """


    manager = LinboImageManager()
    check_linbo_image_group_or_404(manager, image_name)

    run_linbo_image_operation(lambda: manager.delete(image_name))
    return {"image": image_name, "status": "deleted"}


@router.delete("/images/{image_name}/diff", name="Delete an image's differential image")
def delete_image_diff(
    image_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Delete only the differential image of a LINBO image.

    ### Access
    - global-administrators

    \f
    :param image_name: Name of the LINBO image
    """


    manager = LinboImageManager()
    group = check_linbo_image_group_or_404(manager, image_name)

    if group.diff_image is None:
        raise HTTPException(status_code=404, detail=f"Image {image_name} has no differential image")

    run_linbo_image_operation(lambda: manager.delete(image_name, diff=True))
    return {"image": image_name, "status": "diff-deleted"}


@router.delete("/images/{image_name}/backups/{timestamp}", name="Delete one backup of an image")
def delete_image_backup(
    image_name: str,
    timestamp: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Delete a single backup of a LINBO image.

    ### Access
    - global-administrators

    \f
    :param image_name: Name of the LINBO image
    :param timestamp: Backup timestamp, `YYYYMMDDhhmm`
    """


    manager = LinboImageManager()
    group = check_linbo_image_group_or_404(manager, image_name)
    date = check_linbo_backup_date_or_404(group, timestamp)

    run_linbo_image_operation(lambda: manager.delete(image_name, date=date))
    return {"image": image_name, "backup": timestamp, "status": "deleted"}


@router.post("/images/{image_name}/backups/{timestamp}/restore", name="Restore a backup of an image")
def restore_image_backup(
    image_name: str,
    timestamp: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Restore a backup over the base image.

    The base image is moved to a new backup first, so the operation is
    reversible.

    ### Access
    - global-administrators

    \f
    :param image_name: Name of the LINBO image
    :param timestamp: Backup timestamp to restore, `YYYYMMDDhhmm`
    """


    manager = LinboImageManager()
    group = check_linbo_image_group_or_404(manager, image_name)
    date = check_linbo_backup_date_or_404(group, timestamp)

    run_linbo_image_operation(lambda: manager.restore(image_name, date))
    return {"image": image_name, "backup": timestamp, "status": "restored"}


@router.post("/images/{image_name}/rename", name="Rename a LINBO image")
def rename_image(
    image_name: str,
    body: LinboImageNameBody,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Rename a LINBO image with its backups, differential image and sidecars.

    ### Access
    - global-administrators

    \f
    :param image_name: Current name of the LINBO image
    :param body: New name
    """


    manager = LinboImageManager()
    check_linbo_image_group_or_404(manager, image_name)
    new_name = check_new_linbo_image_name_or_409(manager, body.new_name)

    run_linbo_image_operation(lambda: manager.rename(image_name, new_name))
    return {"image": new_name, "previousName": image_name, "status": "renamed"}


@router.post("/images/{image_name}/duplicate", name="Duplicate a LINBO image")
def duplicate_image(
    image_name: str,
    body: LinboImageNameBody,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Copy a LINBO image under a new name, without its backups.

    ### Access
    - global-administrators

    \f
    :param image_name: Name of the LINBO image to copy
    :param body: Name for the copy
    """


    manager = LinboImageManager()
    check_linbo_image_group_or_404(manager, image_name)
    new_name = check_new_linbo_image_name_or_409(manager, body.new_name)

    run_linbo_image_operation(lambda: manager.duplicate(image_name, new_name))
    return {"image": new_name, "sourceImage": image_name, "status": "duplicated"}


# TODO: HTTP verb inconsistency — full overwrite (upsert), compare with write_startconf
# (same kind of operation) which uses POST instead
@router.put("/images/{image_name}/extras", name="Write an image's sidecar files")
def save_image_extras(
    image_name: str,
    body: LinboImageExtrasBody,
    timestamp: str | None = Query(
        None,
        description="Write the sidecars of this backup instead of the base image",
    ),
    diff: bool = Query(False, description="Write the sidecars of the differential image"),
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Write the `info`, `desc`, `vdi`, `reg`, `postsync` and `prestart` sidecars.

    A field left out of the body deletes that sidecar, which is why `info` is
    required — an image without it cannot be read back. `timestamp` and `diff`
    are mutually exclusive.

    ### Access
    - global-administrators

    \f
    :param image_name: Name of the LINBO image
    :param body: Sidecar contents
    :param timestamp: Backup timestamp, `YYYYMMDDhhmm`
    :param diff: Target the differential image
    """


    if timestamp and diff:
        raise HTTPException(status_code=400, detail="timestamp and diff are mutually exclusive")

    manager = LinboImageManager()
    group = check_linbo_image_group_or_404(manager, image_name)

    if timestamp:
        check_linbo_backup_date_or_404(group, timestamp)

    if diff and group.diff_image is None:
        raise HTTPException(status_code=404, detail=f"Image {image_name} has no differential image")

    run_linbo_image_operation(
        lambda: manager.save_extras(image_name, body.model_dump(), timestamp=timestamp, diff=diff)
    )
    return {"image": image_name, "status": "saved"}
