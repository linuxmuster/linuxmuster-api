"""
LINBO Docker sync endpoints.

Provides read-only access to LINBO host data, start.conf files,
GRUB configs, and DHCP exports for LINBO Docker sync mode.
Uses file-based delta detection via mtimes (no database required).
"""

import hashlib
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse

from security import AuthenticatedUser, RoleChecker

from .body_schemas import LinboBatchIds, LinboBatchMacs

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/linbo",
    tags=["LINBO"],
    responses={404: {"description": "Not found"}},
)

# --- Paths ---

LINBO_DIR = Path("/srv/linbo")
GRUB_DIR = LINBO_DIR / "boot" / "grub"
DHCP_SUBNETS_PATH = Path("/etc/dhcp/subnets.conf")
DHCP_DEVICES_DIR = Path("/etc/dhcp/devices")

# --- MAC / IP validation ---

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_TAG_RE = re.compile(r"[^a-zA-Z0-9_-]")
_SCHOOL_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")


def _validate_school(school: str) -> None:
    """Validate school name to prevent path traversal. Raises 400 if invalid."""
    if not _SCHOOL_RE.match(school):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid school name: {school!r}. Must match [a-zA-Z0-9][a-zA-Z0-9_-]*"
        )


def _devices_csv_path(school: str) -> Path:
    """Resolve devices.csv path for a given school (LMN convention)."""
    if school != "default-school":
        prefix = f"{school}."
    else:
        prefix = ""
    return Path(f"/etc/linuxmuster/sophomorix/{school}/{prefix}devices.csv")


# ── Helpers ──────────────────────────────────────────────────────────


def _normalize_mac(raw: str) -> str | None:
    """Normalize MAC to uppercase colon-separated. Returns None if invalid."""
    raw = raw.strip()
    if not _MAC_RE.match(raw):
        return None
    return raw.upper().replace("-", ":")


def _get_mtime(path: Path) -> datetime | None:
    """Return file mtime as UTC datetime, or None if missing."""
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None


def _mtime_cursor(dt: datetime | None) -> str:
    """Convert datetime to unix-timestamp cursor string."""
    if dt is None:
        return "0"
    return str(int(dt.timestamp()))


def _parse_devices_csv(school: str = "default-school") -> tuple[list[dict], datetime | None]:
    """Parse devices.csv for a given school into a list of host dicts.

    Returns (hosts, file_mtime). Skips comment lines and invalid MACs.
    CSV columns (semicolon-separated):
      0=room, 1=hostname, 2=hostgroup, 3=mac, 4=ip, 8=sophomorixRole, 10=pxeFlag
    """
    csv_path = _devices_csv_path(school)
    try:
        text = csv_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"School '{school}' not found (no devices.csv at {csv_path})"
        )
    except OSError as exc:
        logger.error("Failed to read devices.csv: %s", exc)
        return [], None

    mtime = _get_mtime(csv_path)
    hosts = []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        fields = line.split(";")
        if len(fields) < 5:
            continue

        # Pad to 15 columns
        while len(fields) < 15:
            fields.append("")

        mac = _normalize_mac(fields[3])
        if mac is None:
            continue

        raw_ip = fields[4].strip()
        ip = raw_ip if raw_ip and _IP_RE.match(raw_ip) else None

        config = fields[2].strip()

        try:
            pxe_flag = int(fields[10].strip()) if fields[10].strip() else 1
        except ValueError:
            pxe_flag = 1

        pxe_enabled = pxe_flag > 0 and config.lower() != "nopxe"

        hosts.append({
            "mac": mac,
            "hostname": fields[1].strip(),
            "ip": ip,
            "room": fields[0].strip(),
            "school": school,
            "hostgroup": config,
            "pxeEnabled": pxe_enabled,
            "pxeFlag": pxe_flag,
            "dhcpOptions": "",
            "startConfId": config,
            "updatedAt": mtime.isoformat() if mtime else None,
        })

    return hosts, mtime


def _list_startconf_ids() -> list[str]:
    """Return list of start.conf group IDs from /srv/linbo/start.conf.*."""
    ids = []
    for p in sorted(LINBO_DIR.glob("start.conf.*")):
        group = p.name.removeprefix("start.conf.")
        if group:
            ids.append(group)
    return ids


def _list_grub_cfg_ids() -> list[str]:
    """Return list of GRUB config group IDs from /srv/linbo/boot/grub/*.cfg."""
    ids = []
    for p in sorted(GRUB_DIR.glob("*.cfg")):
        group = p.stem
        if group:
            ids.append(group)
    return ids


def _generate_dnsmasq_proxy(hosts: list[dict]) -> str:
    """Generate dnsmasq proxy-DHCP config from host list."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pxe_hosts = [h for h in hosts if h["pxeEnabled"]]

    lines = [
        "#",
        "# LINBO - dnsmasq Configuration (proxy mode)",
        f"# Generated: {ts}",
        f"# Hosts: {len(pxe_hosts)}",
        "#",
        "",
        "# Proxy DHCP mode - no IP assignment, PXE only",
        "port=0",
        "dhcp-range=10.0.0.0,proxy",
        "log-dhcp",
        "",
        "interface=eth0",
        "bind-interfaces",
        "",
        "# PXE boot architecture detection",
        "dhcp-match=set:bios,option:client-arch,0",
        "dhcp-match=set:efi32,option:client-arch,6",
        "dhcp-match=set:efi64,option:client-arch,7",
        "dhcp-match=set:efi64,option:client-arch,9",
        "",
        "dhcp-boot=tag:bios,boot/grub/i386-pc/core.0,10.0.0.1",
        "dhcp-boot=tag:efi32,boot/grub/i386-efi/core.efi,10.0.0.1",
        "dhcp-boot=tag:efi64,boot/grub/x86_64-efi/core.efi,10.0.0.1",
        "",
    ]

    if pxe_hosts:
        # Group by config
        config_groups: dict[str, list[dict]] = {}
        for h in pxe_hosts:
            config_groups.setdefault(h["hostgroup"], []).append(h)

        lines.append("# Host config assignments")
        for h in pxe_hosts:
            tag = _TAG_RE.sub("_", h["hostgroup"])
            lines.append(f"dhcp-host={h['mac']},set:{tag}")
        lines.append("")

        lines.append("# Config name via NIS-Domain (Option 40)")
        for config_name in config_groups:
            if config_name:
                tag = _TAG_RE.sub("_", config_name)
                lines.append(f"dhcp-option=tag:{tag},40,{config_name}")
        lines.append("")

    return "\n".join(lines)


# ── Endpoints ────────────────────────────────────────────────────────

SETUP_INI_PATH = Path("/var/lib/linuxmuster/setup.ini")


def _parse_setup_ini() -> dict:
    """Parse /var/lib/linuxmuster/setup.ini into a flat dict."""
    result = {}
    try:
        for line in SETUP_INI_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("[") or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                result[key.strip()] = value.strip()
    except OSError as exc:
        logger.warning("Failed to read setup.ini: %s", exc)
    return result


@router.get("/server-info", name="LMN server network info for Docker auto-setup")
def get_server_info(
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Server network configuration for Docker auto-setup.

    Returns key values from setup.ini that a LINBO Docker instance needs
    to auto-configure itself (DHCP options, domain, gateway, etc.).
    Used by `setup.sh` to eliminate manual .env editing.

    Also includes the list of available schools so the admin can choose.

    ### Access
    - global-administrators

    \\f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Server configuration dict
    :rtype: dict
    """
    ini = _parse_setup_ini()
    if not ini:
        raise HTTPException(
            status_code=500,
            detail="setup.ini not found or empty"
        )

    # Collect available schools from sophomorix directory
    sophomorix_dir = Path("/etc/linuxmuster/sophomorix")
    schools = []
    if sophomorix_dir.is_dir():
        for d in sorted(sophomorix_dir.iterdir()):
            if d.is_dir() and not d.name.startswith("."):
                # Check if it has a devices.csv (= real school, not just config dir)
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

    Returns status of LINBO data sources (devices.csv, start.conf files,
    GRUB configs). Used by LINBO Docker to verify connectivity.

    ### Access
    - global-administrators

    \\f
    :param school: School name (default: default-school)
    :type school: str
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Health status with file availability
    :rtype: dict
    """
    _validate_school(school)
    csv_path = _devices_csv_path(school)
    devices_ok = csv_path.is_file()
    linbo_ok = LINBO_DIR.is_dir()
    startconfs = len(_list_startconf_ids())
    grub_cfgs = len(_list_grub_cfg_ids())

    return {
        "status": "ok" if devices_ok and linbo_ok else "degraded",
        "devicesCSV": devices_ok,
        "linboDir": linbo_ok,
        "startConfs": startconfs,
        "grubConfigs": grub_cfgs,
    }


@router.get("/changes", name="Delta feed for LINBO sync")
def get_changes(
    since: str = "0",
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Get changes since last sync (delta feed).

    Cursor-based change detection using file modification times.
    Pass `since=0` for a full snapshot of all known entities.
    Pass the `nextCursor` from a previous response for incremental updates.

    The cursor format is a unix timestamp. Changes are detected by comparing
    file mtimes of devices.csv, start.conf.*, and GRUB *.cfg files.

    ### Access
    - global-administrators

    \\f
    :param since: Cursor from previous sync (unix timestamp), or '0' for full snapshot
    :type since: str
    :param school: School name (default: default-school)
    :type school: str
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Delta response with changed entity lists and next cursor
    :rtype: dict
    """
    _validate_school(school)

    # Parse cursor
    try:
        cursor_ts = int(since) if since else 0
    except ValueError:
        cursor_ts = 0

    cursor_dt = (
        datetime.fromtimestamp(cursor_ts, tz=timezone.utc) if cursor_ts > 0
        else None
    )

    # Always parse all known entities (needed for deletion detection)
    all_hosts, _ = _parse_devices_csv(school)
    school_groups = {h["hostgroup"] for h in all_hosts}
    all_host_macs = [h["mac"] for h in all_hosts]
    all_startconf_ids = [id for id in _list_startconf_ids() if id in school_groups]
    all_config_ids = [id for id in _list_grub_cfg_ids() if id in school_groups]

    # Detect changes via mtimes
    devices_mtime = _get_mtime(_devices_csv_path(school))
    hosts_changed_macs: list[str] = []
    deleted_hosts: list[str] = []
    dhcp_changed = False

    # Full snapshot or devices.csv changed?
    devices_modified = (
        cursor_dt is None
        or devices_mtime is None
        or (devices_mtime > cursor_dt)
    )

    if devices_modified:
        hosts_changed_macs = list(all_host_macs)
        dhcp_changed = True

    # Check start.conf files
    startconfs_changed: list[str] = []
    deleted_startconfs: list[str] = []
    for group in all_startconf_ids:
        conf_path = LINBO_DIR / f"start.conf.{group}"
        mtime = _get_mtime(conf_path)
        if cursor_dt is None or (mtime and mtime > cursor_dt):
            startconfs_changed.append(group)

    # Check GRUB configs
    configs_changed: list[str] = []
    for group in all_config_ids:
        cfg_path = GRUB_DIR / f"{group}.cfg"
        mtime = _get_mtime(cfg_path)
        if cursor_dt is None or (mtime and mtime > cursor_dt):
            configs_changed.append(group)

    # Next cursor = current time
    next_cursor = str(int(time.time()))

    return {
        "nextCursor": next_cursor,
        "hostsChanged": hosts_changed_macs,
        "startConfsChanged": startconfs_changed,
        "configsChanged": configs_changed,
        "dhcpChanged": dhcp_changed,
        "deletedHosts": deleted_hosts,
        "deletedStartConfs": deleted_startconfs,
        "allHostMacs": all_host_macs,
        "allStartConfIds": all_startconf_ids,
        "allConfigIds": all_config_ids,
    }


@router.post("/hosts:batch", name="Batch get hosts by MAC")
def batch_get_hosts(
    body: LinboBatchMacs,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Get host records for a list of MAC addresses.

    Parses devices.csv and returns matching host records.
    Used by LINBO Docker for sync mode delta updates.
    Maximum 500 MACs per request.

    ### Access
    - global-administrators

    \\f
    :param body: List of MAC addresses to look up
    :type body: LinboBatchMacs
    :param school: School name (default: default-school)
    :type school: str
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Dict with hosts list
    :rtype: dict
    """
    _validate_school(school)

    if len(body.macs) > 500:
        raise HTTPException(
            status_code=400,
            detail="Maximum 500 MACs per request"
        )

    devices, _ = _parse_devices_csv(school)
    if not devices:
        raise HTTPException(
            status_code=404,
            detail="devices.csv not found or empty"
        )

    macs_upper = {m.upper().replace("-", ":") for m in body.macs}
    hosts = [d for d in devices if d["mac"] in macs_upper]

    if not hosts:
        raise HTTPException(
            status_code=404,
            detail="No hosts found for given MACs"
        )

    return {"hosts": hosts}


@router.post("/startconfs:batch", name="Batch get start.conf files")
def batch_get_startconfs(
    body: LinboBatchIds,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Get start.conf file contents for a list of group IDs.

    Reads start.conf.<group> files from /srv/linbo/ and returns
    their raw content with SHA-256 hash and modification timestamp.

    ### Access
    - global-administrators

    \\f
    :param body: List of start.conf group IDs
    :type body: LinboBatchIds
    :param school: School name (default: default-school)
    :type school: str
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Dict with startConfs list
    :rtype: dict
    """
    _validate_school(school)

    if len(body.ids) > 100:
        raise HTTPException(
            status_code=400,
            detail="Maximum 100 IDs per request"
        )

    results = []
    for group_id in body.ids:
        conf_path = LINBO_DIR / f"start.conf.{group_id}"
        if not conf_path.is_file():
            continue
        try:
            content = conf_path.read_text(encoding="utf-8")
        except OSError:
            continue

        mtime = _get_mtime(conf_path)
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        results.append({
            "id": group_id,
            "content": content,
            "hash": content_hash,
            "updatedAt": mtime.isoformat() if mtime else None,
        })

    if not results:
        raise HTTPException(
            status_code=404,
            detail="No start.conf files found for given IDs"
        )

    return {"startConfs": results}


@router.post("/configs:batch", name="Batch get GRUB configs")
def batch_get_configs(
    body: LinboBatchIds,
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Get GRUB configuration files for a list of group IDs.

    Reads <group>.cfg files from /srv/linbo/boot/grub/ and returns
    their raw content with modification timestamp.

    ### Access
    - global-administrators

    \\f
    :param body: List of GRUB config group IDs
    :type body: LinboBatchIds
    :param school: School name (default: default-school)
    :type school: str
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Dict with configs list
    :rtype: dict
    """
    _validate_school(school)

    if len(body.ids) > 100:
        raise HTTPException(
            status_code=400,
            detail="Maximum 100 IDs per request"
        )

    results = []
    for group_id in body.ids:
        cfg_path = GRUB_DIR / f"{group_id}.cfg"
        if not cfg_path.is_file():
            continue
        try:
            content = cfg_path.read_text(encoding="utf-8")
        except OSError:
            continue

        mtime = _get_mtime(cfg_path)

        results.append({
            "id": group_id,
            "content": content,
            "updatedAt": mtime.isoformat() if mtime else None,
        })

    if not results:
        raise HTTPException(
            status_code=404,
            detail="No GRUB configs found for given IDs"
        )

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

    Exports all PXE-enabled hosts from devices.csv as a dnsmasq
    configuration file for proxy DHCP mode. Supports ETag-based
    conditional requests (If-None-Match).

    ### Access
    - global-administrators

    \\f
    :param request: FastAPI request for ETag header access
    :type request: Request
    :param school: School name (default: default-school)
    :type school: str
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: dnsmasq configuration as plain text
    :rtype: PlainTextResponse
    """
    _validate_school(school)
    devices, mtime = _parse_devices_csv(school)
    if not devices:
        raise HTTPException(
            status_code=404,
            detail="devices.csv not found or empty"
        )

    content = _generate_dnsmasq_proxy(devices)
    etag = hashlib.md5(content.encode()).hexdigest()

    # Conditional GET
    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match.strip('"') == etag:
        return PlainTextResponse(
            content="",
            status_code=304,
            headers={"ETag": f'"{etag}"'},
        )

    return PlainTextResponse(
        content=content,
        headers={
            "ETag": f'"{etag}"',
            "Last-Modified": mtime.strftime("%a, %d %b %Y %H:%M:%S GMT")
            if mtime else "",
        },
    )


@router.get("/grub-configs", name="All GRUB configs for a school")
def get_all_grub_configs(
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Export all GRUB config files for a school.

    Returns the main grub.cfg (always included) plus all {group}.cfg files
    whose group name appears in the school's devices.csv. Used by LINBO Docker
    to sync GRUB configs from the LMN server instead of generating them locally.

    ### Access
    - global-administrators

    \\f
    :param school: School name (default: default-school)
    :type school: str
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Dict with configs list and school name
    :rtype: dict
    """
    _validate_school(school)

    # Get groups from school's devices.csv
    hosts, _ = _parse_devices_csv(school)
    school_groups = {h["hostgroup"] for h in hosts}

    configs = []

    # Always include main grub.cfg (PXE entry point, not school-specific)
    main_cfg = GRUB_DIR / "grub.cfg"
    if main_cfg.is_file():
        try:
            content = main_cfg.read_text(encoding="utf-8")
            mtime = _get_mtime(main_cfg)
            configs.append({
                "id": "grub",
                "filename": "grub.cfg",
                "content": content,
                "updatedAt": mtime.isoformat() if mtime else None,
            })
        except OSError as exc:
            logger.warning("Failed to read grub.cfg: %s", exc)

    # Include group cfgs that belong to this school
    for p in sorted(GRUB_DIR.glob("*.cfg")):
        if p.name == "grub.cfg":
            continue  # Already handled above
        group = p.stem
        if group in school_groups:
            try:
                content = p.read_text(encoding="utf-8")
                mtime = _get_mtime(p)
                configs.append({
                    "id": group,
                    "filename": f"{group}.cfg",
                    "content": content,
                    "updatedAt": mtime.isoformat() if mtime else None,
                })
            except OSError:
                continue

    return {"configs": configs, "school": school, "total": len(configs)}


@router.get(
    "/dhcp/export/isc-dhcp",
    name="ISC DHCP export for school",
)
def dhcp_export_isc(
    school: str = "default-school",
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Export ISC DHCP configuration for a school.

    Returns the subnet definition (subnets.conf) and per-school device
    reservations (devices/{school}.conf) as JSON. These files are generated
    by `linuxmuster-import-devices` on the LMN server. The API only reads
    and serves them — it does NOT regenerate them.

    Used by LINBO Docker to configure a full ISC DHCP server per school VLAN.

    ### Access
    - global-administrators

    \\f
    :param school: School name (default: default-school)
    :type school: str
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: Dict with subnets and devices config content
    :rtype: dict
    """
    _validate_school(school)

    # Validate school existence via devices.csv (raises 404 for unknown schools,
    # consistent with all other endpoints that accept the school parameter).
    _parse_devices_csv(school)

    devices_path = DHCP_DEVICES_DIR / f"{school}.conf"

    # subnets.conf is shared (not per-school)
    subnets = ""
    if DHCP_SUBNETS_PATH.is_file():
        try:
            subnets = DHCP_SUBNETS_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to read subnets.conf: %s", exc)

    # devices/{school}.conf is per-school (may not exist even for a valid school
    # if DHCP hasn't been configured yet — return empty string in that case)
    devices = ""
    if devices_path.is_file():
        try:
            devices = devices_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to read %s: %s", devices_path, exc)
    else:
        logger.info("No DHCP devices config for school %s at %s", school, devices_path)

    subnets_mtime = _get_mtime(DHCP_SUBNETS_PATH)
    devices_mtime = _get_mtime(devices_path)

    return {
        "school": school,
        "subnets": subnets,
        "devices": devices,
        "subnetsUpdatedAt": subnets_mtime.isoformat() if subnets_mtime else None,
        "devicesUpdatedAt": devices_mtime.isoformat() if devices_mtime else None,
    }


# ── Image Manifest ─────────────────────────────────────────────────

IMAGES_DIR = LINBO_DIR / "images"
IMAGE_EXTS = {".qcow2", ".qdiff", ".cloop"}


def _parse_info_file(info_path: Path) -> dict:
    """Parse a .info sidecar file into a dict."""
    result = {}
    try:
        for line in info_path.read_text(encoding="utf-8").splitlines():
            match = re.match(r'^(\w+)="(.*)"', line)
            if match:
                result[match.group(1)] = match.group(2)
    except OSError:
        pass
    return result


def _scan_images() -> list[dict]:
    """Scan /srv/linbo/images/ for QCOW2/QDIFF/CLOOP images.

    Returns a list of image records with metadata from sidecars.
    Skips backup directories.
    """
    images = []
    if not IMAGES_DIR.is_dir():
        return images

    for subdir in sorted(IMAGES_DIR.iterdir()):
        if not subdir.is_dir() or subdir.name.startswith("."):
            continue

        for img_file in sorted(subdir.iterdir()):
            if img_file.suffix not in IMAGE_EXTS:
                continue
            # Skip backups
            if "backup" in str(img_file.relative_to(IMAGES_DIR)):
                continue

            stat = img_file.stat()
            name = img_file.name
            base = subdir.name
            rel_path = f"images/{base}/{name}"

            # Read .md5 sidecar
            md5 = None
            md5_path = img_file.with_suffix(img_file.suffix + ".md5")
            try:
                md5 = md5_path.read_text().strip().split()[0]
            except OSError:
                pass

            # Read .info sidecar
            info = _parse_info_file(img_file.with_suffix(img_file.suffix + ".info"))

            # Read .desc sidecar
            desc = None
            desc_path = img_file.with_suffix(img_file.suffix + ".desc")
            try:
                desc = desc_path.read_text(encoding="utf-8").strip()
            except OSError:
                pass

            # List available sidecars
            sidecars = []
            for sc in [".md5", ".info", ".desc", ".torrent", ".macct", ".reg",
                        ".prestart", ".postsync"]:
                sc_path = subdir / f"{name}{sc}" if sc.startswith(".") else subdir / f"{base}{sc}"
                # Check both image-name based and base-name based sidecars
                for candidate in [img_file.with_suffix(img_file.suffix + sc),
                                   subdir / f"{base}{sc}"]:
                    if candidate.is_file():
                        sidecars.append(sc.lstrip("."))
                        break

            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

            # Build files list (image + sidecars) for download client
            files = [{"name": name, "size": stat.st_size, "type": "image"}]
            for sc in sidecars:
                sc_ext = f".{sc}"
                # Sidecar can be image-name based or base-name based
                for candidate in [img_file.with_suffix(img_file.suffix + sc_ext),
                                   subdir / f"{base}{sc_ext}"]:
                    if candidate.is_file():
                        sc_stat = candidate.stat()
                        files.append({
                            "name": candidate.name,
                            "size": sc_stat.st_size,
                            "type": "sidecar",
                        })
                        break

            images.append({
                "name": name,
                "filename": name,
                "base": base,
                "path": rel_path,
                "size": stat.st_size,
                "md5": md5,
                "info": info if info else None,
                "description": desc,
                "sidecars": sidecars,
                "files": files,
                "updatedAt": mtime.isoformat(),
            })

    return images


@router.get("/images/manifest", name="Image manifest for sync")
def get_image_manifest(
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## List all LINBO images with metadata.

    Scans /srv/linbo/images/ for QCOW2, QDIFF, and CLOOP files.
    Returns image name, size, MD5, .info metadata, and available sidecars.
    Used by LINBO Docker for image sync comparison.

    ### Access
    - global-administrators

    \\f
    :param who: User requesting the data, read from API Token
    :type who: AuthenticatedUser
    :return: List of image records with metadata
    :rtype: dict
    """
    images = _scan_images()
    return {
        "images": images,
        "total": len(images),
        "scannedAt": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/images/download/{image_name}/{filename}",
    name="Download image or sidecar file",
)
@router.head(
    "/images/download/{image_name}/{filename}",
    name="HEAD image or sidecar file",
)
async def download_image_file(
    image_name: str,
    filename: str,
    request: Request,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Download an image or sidecar file with HTTP Range support.

    Streams the file from /srv/linbo/images/{image_name}/{filename}.
    Supports HEAD requests (for size/ETag) and Range requests (for resume).

    ### Access
    - global-administrators

    \\f
    """
    from fastapi.responses import StreamingResponse, Response

    # Sanitize path components
    if "/" in image_name or ".." in image_name or "/" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid path")

    file_path = IMAGES_DIR / image_name / filename
    if not file_path.is_file():
        # Also check base-name sidecars (e.g., win11_pro_edu.prestart)
        base_name = image_name
        file_path = IMAGES_DIR / image_name / filename
        if not file_path.is_file():
            raise HTTPException(status_code=404, detail=f"File not found: {filename}")

    stat = file_path.stat()
    file_size = stat.st_size
    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    etag = hashlib.md5(f"{file_path}:{stat.st_mtime}:{file_size}".encode()).hexdigest()
    last_modified = mtime.strftime("%a, %d %b %Y %H:%M:%S GMT")

    headers = {
        "Content-Length": str(file_size),
        "ETag": f'"{etag}"',
        "Last-Modified": last_modified,
        "Accept-Ranges": "bytes",
    }

    # HEAD request
    if request.method == "HEAD":
        return Response(content=b"", headers=headers)

    # Range request support
    range_header = request.headers.get("range")
    if range_header:
        try:
            range_spec = range_header.replace("bytes=", "")
            start_str, end_str = range_spec.split("-")
            start = int(start_str) if start_str else 0
            end = int(end_str) if end_str else file_size - 1
            end = min(end, file_size - 1)
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
                    "ETag": f'"{etag}"',
                    "Accept-Ranges": "bytes",
                },
                media_type="application/octet-stream",
            )
        except (ValueError, IndexError):
            raise HTTPException(status_code=416, detail="Invalid Range header")

    # Full file download
    def file_iterator():
        with open(file_path, "rb") as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                yield data

    return StreamingResponse(
        file_iterator(),
        headers=headers,
        media_type="application/octet-stream",
    )


# ── Image Upload ───────────────────────────────────────────────────

INCOMING_DIR = IMAGES_DIR / ".incoming"


@router.put(
    "/images/upload/{image_name}/{filename}",
    name="Upload image or sidecar file (chunked)",
)
async def upload_image_file(
    image_name: str,
    filename: str,
    request: Request,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Upload an image or sidecar file with Content-Range support.

    Files are staged in /srv/linbo/images/.incoming/{image_name}/.
    Supports chunked upload via Content-Range header for resume.
    Call POST /images/upload/{image_name}/complete to finalize.

    ### Access
    - global-administrators

    \\f
    """
    if "/" in image_name or ".." in image_name or "/" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid path")

    staging_dir = INCOMING_DIR / image_name
    staging_dir.mkdir(parents=True, exist_ok=True)
    file_path = staging_dir / filename

    # Parse Content-Range header for chunked upload
    content_range = request.headers.get("content-range")
    if content_range:
        # Content-Range: bytes 0-1048575/28344451072
        try:
            range_spec = content_range.replace("bytes ", "")
            range_part, total = range_spec.split("/")
            start_str, end_str = range_part.split("-")
            start = int(start_str)
        except (ValueError, IndexError):
            raise HTTPException(status_code=400, detail="Invalid Content-Range")

        body = await request.body()
        with open(file_path, "r+b" if file_path.exists() and start > 0 else "wb") as f:
            f.seek(start)
            f.write(body)

        return {"received": len(body), "offset": start + len(body)}
    else:
        # Full file upload (sidecars)
        body = await request.body()
        file_path.write_bytes(body)
        return {"received": len(body)}


@router.get(
    "/images/upload/{image_name}/{filename}/status",
    name="Check upload status for resume",
)
def upload_status(
    image_name: str,
    filename: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """Check how many bytes have been received for a chunked upload."""
    if "/" in image_name or ".." in image_name or "/" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid path")

    file_path = INCOMING_DIR / image_name / filename
    if not file_path.is_file():
        return {"bytesReceived": 0, "complete": False}

    stat = file_path.stat()
    return {"bytesReceived": stat.st_size, "complete": False}


@router.post(
    "/images/upload/{image_name}/complete",
    name="Finalize image upload",
)
def finalize_upload(
    image_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """
    ## Move uploaded files from staging to final images directory.

    Moves all files from .incoming/{image_name}/ to images/{image_name}/.
    Creates the target directory if needed. Overwrites existing files.

    ### Access
    - global-administrators

    \\f
    """
    import shutil

    if "/" in image_name or ".." in image_name:
        raise HTTPException(status_code=400, detail="Invalid path")

    staging_dir = INCOMING_DIR / image_name
    if not staging_dir.is_dir():
        raise HTTPException(status_code=404, detail="No staged files found")

    target_dir = IMAGES_DIR / image_name
    target_dir.mkdir(parents=True, exist_ok=True)

    moved = []
    for f in staging_dir.iterdir():
        if f.is_file():
            target = target_dir / f.name
            shutil.move(str(f), str(target))
            moved.append(f.name)

    # Clean up staging directory
    try:
        staging_dir.rmdir()
    except OSError:
        pass

    logger.info(f"Image upload finalized: {image_name} ({len(moved)} files)")
    return {"finalized": True, "files": moved}


@router.delete(
    "/images/upload/{image_name}",
    name="Cancel/cleanup upload",
)
def cancel_upload(
    image_name: str,
    who: AuthenticatedUser = Depends(RoleChecker("G")),
):
    """Clean up staged upload files on cancel or failure."""
    import shutil

    if "/" in image_name or ".." in image_name:
        raise HTTPException(status_code=400, detail="Invalid path")

    staging_dir = INCOMING_DIR / image_name
    if staging_dir.is_dir():
        shutil.rmtree(str(staging_dir))
        return {"cleaned": True}
    return {"cleaned": False, "detail": "No staging directory found"}
