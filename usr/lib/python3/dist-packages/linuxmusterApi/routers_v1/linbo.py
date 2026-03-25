"""
LINBO sync endpoints — thin REST layer over linuxmusterTools.linbo.

All business logic lives in linuxmusterTools.linbo modules.
This router only handles HTTP concerns (auth, validation, responses).
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse, Response

from security import AuthenticatedUser, RoleChecker
from utils.checks import check_valid_school_or_404

from .body_schemas import LinboBatchIds, LinboBatchMacs

# LMNTools imports — all business logic
from linuxmusterTools.linbo.hosts import (
    LinboHostProvider, devices_csv_path,
)
from linuxmusterTools.linbo.config import LinboConfigManager
from linuxmusterTools.linbo.grub import LinboGrubReader
from linuxmusterTools.linbo.dhcp import LinboDhcpExporter
from linuxmusterTools.linbo.changes import LinboChangeTracker
from linuxmusterTools.linbo.image_sync import (
    scan_images,
    resolve_image_file, get_image_file_info,
    receive_upload_chunk, get_upload_status,
    finalize_upload, cancel_upload,
    validate_image_path,
)
from linuxmusterTools.lmnfile import LMNFile

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/linbo",
    tags=["LINBO"],
    responses={404: {"description": "Not found"}},
)

# --- Paths ---

LINBO_DIR = Path("/srv/linbo")
IMAGES_DIR = LINBO_DIR / "images"


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/server-info", name="LMN server network info for auto-setup")
def get_server_info(
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Server network configuration for auto-setup.

    \\f
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

    sophomorix_dir = Path("/etc/linuxmuster/sophomorix")
    schools = []
    if sophomorix_dir.is_dir():
        for d in sorted(sophomorix_dir.iterdir()):
            if d.is_dir() and not d.name.startswith("."):
                csv_name = "devices.csv" if d.name == "default-school" else f"{d.name}.devices.csv"
                if (d / csv_name).is_file():
                    schools.append(d.name)

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

    \\f
    :param school: School name (default: default-school)
    :type school: str
    """
    check_valid_school_or_404(school)
    csv_path = devices_csv_path(school)
    config_mgr = LinboConfigManager()
    grub_reader = LinboGrubReader()

    return {
        "status": "ok" if csv_path.is_file() and LINBO_DIR.is_dir() else "degraded",
        "devicesCSV": csv_path.is_file(),
        "linboDir": LINBO_DIR.is_dir(),
        "startConfs": len(config_mgr.list_startconf_ids()),
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

    \\f
    :param since: Cursor from previous sync (unix timestamp), or '0' for full snapshot
    :param school: School name (default: default-school)
    """
    check_valid_school_or_404(school)
    tracker = LinboChangeTracker(school=school)
    return tracker.get_changes(since_cursor=since)


@router.post("/hosts:batch", name="Batch get hosts by MAC")
def batch_get_hosts(
    body: LinboBatchMacs,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Get host records for a list of MAC addresses.

    \\f
    :param body: List of MAC addresses to look up
    :param school: School name (default: default-school)
    """
    check_valid_school_or_404(school)

    if len(body.macs) > 500:
        raise HTTPException(status_code=400, detail="Maximum 500 MACs per request")

    provider = LinboHostProvider(school)
    hosts = provider.get_hosts_by_macs(body.macs)

    if not hosts:
        raise HTTPException(status_code=404, detail="No hosts found for given MACs")

    return {"hosts": hosts}


@router.post("/startconfs:batch", name="Batch get start.conf files")
def batch_get_startconfs(
    body: LinboBatchIds,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Get start.conf file contents for a list of group IDs.

    \\f
    :param body: List of start.conf group IDs
    :param school: School name (default: default-school)
    """
    check_valid_school_or_404(school)

    if len(body.ids) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 IDs per request")

    config_mgr = LinboConfigManager()
    results = config_mgr.get_raw_startconfs(body.ids)

    if not results:
        raise HTTPException(status_code=404, detail="No start.conf files found for given IDs")

    return {"startConfs": results}


@router.post("/configs:batch", name="Batch get GRUB configs")
def batch_get_configs(
    body: LinboBatchIds,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Get GRUB configuration files for a list of group IDs.

    \\f
    :param body: List of GRUB config group IDs
    :param school: School name (default: default-school)
    """
    check_valid_school_or_404(school)

    if len(body.ids) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 IDs per request")

    grub_reader = LinboGrubReader()
    results = grub_reader.get_configs_by_ids(body.ids)

    if not results:
        raise HTTPException(status_code=404, detail="No GRUB configs found for given IDs")

    return {"configs": results}


@router.get(
    "/dhcp/export/dnsmasq-proxy",
    name="DHCP export for dnsmasq proxy mode",
    response_class=PlainTextResponse,
)
def dhcp_export_dnsmasq(
    request: Request,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Generate dnsmasq proxy-DHCP configuration.

    \\f
    :param school: School name (default: default-school)
    """
    check_valid_school_or_404(school)

    provider = LinboHostProvider(school)
    try:
        devices, mtime = provider.parse_devices_csv()
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
    if mtime:
        headers["Last-Modified"] = mtime.strftime("%a, %d %b %Y %H:%M:%S GMT")

    return PlainTextResponse(content=content, headers=headers)


@router.get("/grub-configs", name="All GRUB configs for a school")
def get_all_grub_configs(
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Export all GRUB config files for a school.

    \\f
    :param school: School name (default: default-school)
    """
    check_valid_school_or_404(school)

    provider = LinboHostProvider(school)
    try:
        school_groups = provider.get_school_groups()
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

    \\f
    :param school: School name (default: default-school)
    """
    check_valid_school_or_404(school)

    provider = LinboHostProvider(school)
    try:
        provider.parse_devices_csv()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"School '{school}' not found")

    exporter = LinboDhcpExporter()
    return exporter.get_isc_dhcp(school)


# ── Image Manifest ─────────────────────────────────────────────────


@router.get("/images/manifest", name="Image manifest for sync")
def get_image_manifest(
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## List all LINBO images with metadata.

    \\f
    """
    images = scan_images()
    return {
        "images": images,
        "total": len(images),
        "scannedAt": datetime.now(timezone.utc).isoformat(),
    }


# ── Image Download ─────────────────────────────────────────────────


@router.get("/images/download/{image_name}/{filename}", name="Download image or sidecar file")
@router.head("/images/download/{image_name}/{filename}", name="HEAD image or sidecar file")
async def download_image_file(
    image_name: str,
    filename: str,
    request: Request,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Download an image or sidecar file with HTTP Range support.

    \\f
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


@router.put("/images/upload/{image_name}/{filename}", name="Upload image or sidecar file (chunked)")
async def upload_image_file(
    image_name: str, filename: str, request: Request,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """Upload an image or sidecar file with Content-Range support. \\f"""
    try:
        validate_image_path(image_name)
        validate_image_path(filename)
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
    result = receive_upload_chunk(IMAGES_DIR, image_name, filename, body, offset)
    return result


@router.get("/images/upload/{image_name}/{filename}/status", name="Check upload status for resume")
def upload_status_endpoint(
    image_name: str, filename: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """Check how many bytes have been received for a chunked upload. \\f"""
    try:
        return get_upload_status(IMAGES_DIR, image_name, filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/images/upload/{image_name}/complete", name="Finalize image upload")
def finalize_upload_endpoint(
    image_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """Move uploaded files from staging to final images directory.

    If the target directory already contains image files, they are backed up
    to a timestamped subdirectory before being replaced.
    \\f"""
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
    """Clean up staged upload files on cancel or failure. \\f"""
    try:
        return cancel_upload(IMAGES_DIR, image_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
