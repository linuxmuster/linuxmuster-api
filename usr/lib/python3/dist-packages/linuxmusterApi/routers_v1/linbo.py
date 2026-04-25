"""
LINBO sync endpoints — thin REST layer over linuxmusterTools.linbo.

All business logic lives in linuxmusterTools.linbo modules.
This router only handles HTTP concerns (auth, validation, responses).
"""

import logging
import os.path
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request as FARequest
from fastapi.responses import PlainTextResponse, StreamingResponse, Response

from security import AuthenticatedUser, RoleChecker
from utils.checks import check_valid_school_or_404
from .body_schemas import LinboBatchMacs


from linuxmusterTools.ldapconnector import LMNLdapReader as lr
from linuxmusterTools.devices import Devices

from linuxmusterTools.linbo import *
from linuxmusterTools.lmnfile import LMNFile
from linuxmusterTools.common.checks import NameChecker


name_checker = NameChecker()
logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/linbo",
    tags=["LINBO"],
    responses={404: {"description": "Not found"}},
)

# --- Paths ---

LINBO_DIR = Path("/srv/linbo")
IMAGES_DIR = LINBO_DIR / "images"


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
    config_ids = LinboConfigManager().linbo_groups()
    grub_reader = LinboGrubReader()

    return {
        "status": "ok" if csv_path_exists and LINBO_DIR.is_dir() else "degraded",
        "devicesCSV": csv_path_exists,
        "linboDir": LINBO_DIR.is_dir(),
        "startConfs": len(config_ids),
        "grubConfigs": len(grub_reader.list_grub_cfg_ids()),
    }


@router.get("/changes", name="Delta feed for LINBO sync")
def get_changes(
    since: str = "0",
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Get changes since last sync (delta feed).

    ### Access
    - global-administrators

    \f
    :param since: Cursor from previous sync (unix timestamp), or '0' for full snapshot
    :param school: School name (default: default-school)
    """


    check_valid_school_or_404(school)
    tracker = LinboChangeTracker(school=school)
    return tracker.get_changes(since_cursor=since)


@router.post("/hosts/query", name="Query hosts by MAC address list")
def query_hosts(
    body: LinboBatchMacs,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Get host records for a list of MAC addresses.

    ### Access
    - global-administrators

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
def dhcp_export_dnsmasq(
    request: FARequest,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Generate dnsmasq proxy-DHCP configuration.

    ### Access
    - global-administrators

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
def get_all_grub_configs(
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Export all GRUB config files for a school.

    ### Access
    - global-administrators

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
def dhcp_export_isc(
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Export ISC DHCP configuration for a school.

    ### Access
    - global-administrators

    \f
    :param school: School name (default: default-school)
    """


    check_valid_school_or_404(school)

    exporter = LinboDhcpExporter()
    return exporter.get_isc_dhcp(school)


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
async def download_image_file(
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
        return receive_upload_chunk(IMAGES_DIR, image_name, filename, body, offset)
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
