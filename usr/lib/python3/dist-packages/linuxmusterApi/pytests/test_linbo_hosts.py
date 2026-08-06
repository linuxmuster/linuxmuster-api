import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException

from linuxmusterTools.linbo import LinboBootLogs

from routers_v1 import linbo
from routers_v1.body_schemas import LinboHostScanBody, LinboWolBody
from security import RoleChecker


MAX_MACS = linbo.MAX_HOSTS_PER_SCAN
TOO_MANY_MACS_DETAIL = f"Maximum {MAX_MACS} MACs per request"
NO_MACS_DETAIL = "At least one MAC address is required"


def _macs(count):
    """Distinct MACs — a two-digit hex suffix starts repeating past 255."""

    return [f"00:00:00:00:{index // 256:02x}:{index % 256:02x}" for index in range(count)]


@pytest.fixture
def linbo_backends(monkeypatch):
    devices = Mock()
    boot_logs = Mock()
    scan = AsyncMock(return_value=[])
    wol = Mock(return_value={})
    image_status = Mock(return_value={})
    check_school = Mock(side_effect=lambda school: school)

    monkeypatch.setattr(linbo, "Devices", lambda school: devices)
    monkeypatch.setattr(linbo, "LinboBootLogs", lambda: boot_logs)
    monkeypatch.setattr(linbo, "scan_hosts", scan)
    monkeypatch.setattr(linbo, "send_wol_bulk", wol)
    monkeypatch.setattr(linbo, "get_host_image_status", image_status)
    monkeypatch.setattr(linbo, "check_valid_school_or_404", check_school)
    return devices, boot_logs, scan, wol, image_status, check_school


@pytest.fixture
def real_boot_logs(monkeypatch, tmp_path):
    """A real LinboBootLogs, so the library's filename guard actually runs."""

    log_dir = tmp_path / "linbo"
    log_dir.mkdir()
    (log_dir / "pc100.log").write_text("sync finished")
    secret = tmp_path / "shadow"
    secret.write_text("root:!:19000:0:99999:7:::")

    monkeypatch.setattr(linbo, "LinboBootLogs", lambda: LinboBootLogs(str(log_dir)))
    return log_dir, secret


# ── Routing and access ─────────────────────────────────────────────


def test_new_routes_are_registered():
    expected = {
        ("POST", "/linbo/hosts/scan"),
        ("POST", "/linbo/wol"),
        ("GET", "/linbo/hosts/image-status"),
        ("GET", "/linbo/boot-logs"),
        ("GET", "/linbo/boot-logs/{filename}"),
        ("DELETE", "/linbo/boot-logs/{filename}"),
    }
    actual = {
        (method, route.path)
        for route in linbo.router.routes
        for method in route.methods
    }
    assert expected <= actual


def test_every_linbo_route_is_global_admin_only():
    # An invariant over the whole router rather than a pinned route list: this
    # router carries endpoints from several features, and a new one that forgets
    # its Depends(RoleChecker("G")) has to fail here. This checks the declaration
    # only — TestLinbo in test_misc.py covers the enforcement over HTTP.
    for route in linbo.router.routes:
        checkers = [
            dependency.call
            for dependency in route.dependant.dependencies
            if isinstance(dependency.call, RoleChecker)
        ]
        assert len(checkers) == 1, f"{route.path} has {len(checkers)} role checkers"
        assert checkers[0].roles == ["globaladministrator"], route.path


# ── Scan ───────────────────────────────────────────────────────────
#
# probe_hosts is async: it awaits the library's scan_hosts coroutine directly
# instead of running it through a sync wrapper, so it never ties up an AnyIO
# worker thread for the duration of the scan. Calls below go through
# asyncio.run() and the mock is an AsyncMock accordingly.


def test_scan_without_macs_probes_every_client(linbo_backends):
    devices, _, scan, _, _, check_school = linbo_backends
    clients = [{"mac": "00:11:22:33:44:55", "ip": "10.0.0.100", "hostname": "pc100"}]
    devices.get_clients.return_value = clients
    scan.return_value = [
        {
            "mac": "00:11:22:33:44:55",
            "ip": "10.0.0.100",
            "hostname": "pc100",
            "online": True,
            "lastSeen": "2026-03-24T11:42:00+00:00",
        },
    ]

    result = asyncio.run(linbo.probe_hosts(LinboHostScanBody(), "default-school", None))

    check_school.assert_called_once_with("default-school")
    scan.assert_called_once_with(clients, concurrency=linbo.SCAN_CONCURRENCY)
    devices.get_hosts_by_macs.assert_not_called()
    assert result["hosts"] == scan.return_value


def test_scan_with_macs_probes_only_those_hosts(linbo_backends):
    devices, _, scan, _, _, _ = linbo_backends
    macs = ["00:11:22:33:44:55"]
    hosts = [{"mac": macs[0], "ip": "10.0.0.100", "hostname": "pc100"}]
    devices.get_hosts_by_macs.return_value = hosts

    asyncio.run(linbo.probe_hosts(LinboHostScanBody(macs=macs), "default-school", None))

    devices.get_hosts_by_macs.assert_called_once_with(macs)
    devices.get_clients.assert_not_called()
    scan.assert_called_once_with(hosts, concurrency=linbo.SCAN_CONCURRENCY)


def test_scan_validates_the_school_before_touching_the_filesystem(linbo_backends):
    devices, _, scan, _, _, check_school = linbo_backends
    check_school.side_effect = HTTPException(status_code=404, detail="Invalid school")

    with pytest.raises(HTTPException) as error:
        asyncio.run(linbo.probe_hosts(LinboHostScanBody(), "../../tmp", None))

    assert error.value.status_code == 404
    devices.get_clients.assert_not_called()
    devices.get_hosts_by_macs.assert_not_called()
    scan.assert_not_called()


def test_scan_rejects_more_than_the_mac_cap(linbo_backends):
    _, _, scan, _, _, _ = linbo_backends
    body = LinboHostScanBody(macs=_macs(MAX_MACS + 1))

    with pytest.raises(HTTPException) as error:
        asyncio.run(linbo.probe_hosts(body, "default-school", None))

    assert error.value.status_code == 400
    assert error.value.detail == TOO_MANY_MACS_DETAIL
    scan.assert_not_called()


def test_scan_accepts_exactly_the_mac_cap(linbo_backends):
    devices, _, scan, _, _, _ = linbo_backends
    macs = _macs(MAX_MACS)
    hosts = [{"mac": mac, "ip": "10.0.0.100", "hostname": "pc100"} for mac in macs]
    devices.get_hosts_by_macs.return_value = hosts

    asyncio.run(linbo.probe_hosts(LinboHostScanBody(macs=macs), "default-school", None))

    scan.assert_called_once_with(hosts, concurrency=linbo.SCAN_CONCURRENCY)


def test_scan_caps_the_resolved_host_list_too(linbo_backends):
    # An empty MAC list resolves to every client of the school, which the request
    # cap never sees.
    devices, _, scan, _, _, _ = linbo_backends
    devices.get_clients.return_value = [
        {"mac": mac, "ip": "10.0.0.1", "hostname": "pc"} for mac in _macs(MAX_MACS + 1)
    ]

    with pytest.raises(HTTPException) as error:
        asyncio.run(linbo.probe_hosts(LinboHostScanBody(), "default-school", None))

    assert error.value.status_code == 400
    assert str(MAX_MACS) in error.value.detail
    scan.assert_not_called()


def test_scan_without_any_host_is_404(linbo_backends):
    devices, _, scan, _, _, _ = linbo_backends
    devices.get_clients.return_value = []

    with pytest.raises(HTTPException) as error:
        asyncio.run(linbo.probe_hosts(LinboHostScanBody(), "default-school", None))

    assert error.value.status_code == 404
    assert error.value.detail == "No hosts found"
    scan.assert_not_called()


def test_scan_timestamp_is_utc_aware(linbo_backends):
    devices, _, _, _, _, _ = linbo_backends
    devices.get_clients.return_value = [{"mac": "00:11:22:33:44:55", "ip": "10.0.0.100"}]

    result = asyncio.run(linbo.probe_hosts(LinboHostScanBody(), "default-school", None))
    scanned_at = datetime.fromisoformat(result["scannedAt"])

    # A naive datetime.now() parses back with tzinfo None; astimezone() would be
    # aware but local.
    assert scanned_at.tzinfo is not None
    assert scanned_at.utcoffset() == timedelta(0)


# ── Wake-on-LAN ────────────────────────────────────────────────────


def test_wol_delegates_with_packet_parameters(linbo_backends):
    _, _, _, wol, _, _ = linbo_backends
    macs = ["00:11:22:33:44:55"]
    wol.return_value = {
        "total": 1,
        "successful": 1,
        "failed": 0,
        "results": [{"macAddress": macs[0], "success": True, "error": None}],
    }

    body = LinboWolBody(macs=macs, broadcast="10.0.0.255", port=7, count=5)
    result = linbo.wake_hosts(body, None)

    # broadcast is an IPvAnyAddress on the model and a str on the socket call.
    wol.assert_called_once_with(macs, broadcast="10.0.0.255", port=7, count=5)
    assert result == wol.return_value


def test_wol_falls_back_to_the_schema_packet_defaults(linbo_backends):
    _, _, _, wol, _, _ = linbo_backends
    macs = ["00:11:22:33:44:55"]

    linbo.wake_hosts(LinboWolBody(macs=macs), None)

    wol.assert_called_once_with(macs, broadcast=None, port=9, count=3)


@pytest.mark.parametrize(
    "field,value",
    [
        ("count", 0),
        ("count", -5),
        ("count", 1000000),
        ("port", 0),
        ("port", 70000),
        ("broadcast", "not-an-address"),
    ],
)
def test_wol_packet_parameters_are_bounded_by_the_schema(field, value):
    # Rejected before a socket is opened: an unbounded count is multiplied by the
    # MAC count inside a blocking send loop, and a negative one sends nothing while
    # send_wol_bulk still reports every host as successful.
    with pytest.raises(ValueError):
        LinboWolBody(macs=["00:11:22:33:44:55"], **{field: value})


def test_wol_without_macs_is_rejected(linbo_backends):
    _, _, _, wol, _, _ = linbo_backends

    with pytest.raises(HTTPException) as error:
        linbo.wake_hosts(LinboWolBody(macs=[]), None)

    assert error.value.status_code == 400
    assert error.value.detail == NO_MACS_DETAIL
    wol.assert_not_called()


def test_wol_rejects_more_than_the_mac_cap(linbo_backends):
    _, _, _, wol, _, _ = linbo_backends
    body = LinboWolBody(macs=_macs(MAX_MACS + 1))

    with pytest.raises(HTTPException) as error:
        linbo.wake_hosts(body, None)

    assert error.value.status_code == 400
    assert error.value.detail == TOO_MANY_MACS_DETAIL
    wol.assert_not_called()


def test_wol_accepts_exactly_the_mac_cap(linbo_backends):
    _, _, _, wol, _, _ = linbo_backends
    macs = _macs(MAX_MACS)

    linbo.wake_hosts(LinboWolBody(macs=macs), None)

    wol.assert_called_once_with(macs, broadcast=None, port=9, count=3)


# ── Image status ───────────────────────────────────────────────────


def test_image_status_reports_one_entry_per_host(linbo_backends):
    _, _, _, _, image_status, _ = linbo_backends
    image_status.return_value = {
        "pc100": {
            "lastSync": "2026-03-24T11:42:00.000Z",
            "action": "applied",
            "image": "win11_pro.qcow2",
            "imageVersion": "202601271107",
        },
        "pc101": {
            "lastSync": "2026-03-24T11:44:00.000Z",
            "action": "applied",
            "image": "win11_pro.qcow2",
            "imageVersion": "202601271107",
        },
        "pc102": {
            "lastSync": "2026-03-25T08:03:00.000Z",
            "action": "created",
            "image": "ubuntu2404.qcow2",
            "imageVersion": None,
        },
    }

    result = linbo.hosts_image_status(None)

    assert result["hosts"] == image_status.return_value
    assert result["total"] == 3


# ── Boot logs ──────────────────────────────────────────────────────


def test_boot_logs_are_listed_with_one_entry_per_file(linbo_backends):
    _, boot_logs, _, _, _, _ = linbo_backends
    boot_logs.list_logs.return_value = [
        {"filename": "pc102.log", "size": 4096, "modifiedAt": "2026-03-25T08:03:11+00:00"},
        {"filename": "pc101.log", "size": 2048, "modifiedAt": "2026-03-24T11:44:02+00:00"},
        {"filename": "pc100.log", "size": 12, "modifiedAt": "2026-03-24T11:42:00+00:00"},
    ]

    result = linbo.list_boot_logs(None)

    assert result["logs"] == boot_logs.list_logs.return_value
    assert result["total"] == 3


def test_boot_log_is_returned_as_plain_text(linbo_backends):
    _, boot_logs, _, _, _, _ = linbo_backends
    boot_logs.read_log.return_value = "sync finished"

    response = linbo.read_boot_log("pc100.log", None)

    boot_logs.read_log.assert_called_once_with("pc100.log")
    assert response.body == b"sync finished"
    assert response.media_type == "text/plain"


def test_an_empty_boot_log_is_returned_as_an_empty_body(linbo_backends):
    # The route must test `content is None`, not falsiness — a zero-byte log reads
    # back as "" and is a 200, not a 404.
    _, boot_logs, _, _, _, _ = linbo_backends
    boot_logs.read_log.return_value = ""

    response = linbo.read_boot_log("empty.log", None)

    assert response.status_code == 200
    assert response.body == b""


def test_missing_boot_log_is_404(linbo_backends):
    _, boot_logs, _, _, _, _ = linbo_backends
    boot_logs.read_log.return_value = None

    with pytest.raises(HTTPException) as error:
        linbo.read_boot_log("nope.log", None)

    assert error.value.status_code == 404


def test_read_log_value_error_maps_to_400(linbo_backends):
    _, boot_logs, _, _, _, _ = linbo_backends
    boot_logs.read_log.side_effect = ValueError("Unsafe filename: ../../etc/shadow")

    with pytest.raises(HTTPException) as error:
        linbo.read_boot_log("../../etc/shadow", None)

    assert error.value.status_code == 400
    assert "Unsafe filename" in error.value.detail


def test_an_oversized_boot_log_is_413_not_400(linbo_backends):
    # read_log raises ValueError both for an unsafe name and for a log over the
    # size limit. A log the list endpoint just advertised is not a bad request.
    _, boot_logs, _, _, _, _ = linbo_backends
    boot_logs.read_log.side_effect = ValueError("File too large: 7340032 bytes (max 5242880)")

    with pytest.raises(HTTPException) as error:
        linbo.read_boot_log("pc100.log", None)

    assert error.value.status_code == 413


def test_boot_log_deletion_delegates_the_filename(linbo_backends):
    _, boot_logs, _, _, _, _ = linbo_backends
    boot_logs.delete_log.return_value = True

    result = linbo.delete_boot_log("pc100.log", None)

    boot_logs.delete_log.assert_called_once_with("pc100.log")
    assert result == {"filename": "pc100.log", "status": "deleted"}


def test_deleting_a_missing_boot_log_is_404(linbo_backends):
    _, boot_logs, _, _, _, _ = linbo_backends
    boot_logs.delete_log.return_value = False

    with pytest.raises(HTTPException) as error:
        linbo.delete_boot_log("nope.log", None)

    assert error.value.status_code == 404
    boot_logs.delete_log.assert_called_once_with("nope.log")


def test_a_boot_log_deleted_concurrently_is_404(linbo_backends):
    # logrotate rotates this directory, so a log can vanish between delete_log's
    # is_file() and its unlink().
    _, boot_logs, _, _, _, _ = linbo_backends
    boot_logs.delete_log.side_effect = FileNotFoundError("gone")

    with pytest.raises(HTTPException) as error:
        linbo.delete_boot_log("pc100.log", None)

    assert error.value.status_code == 404


def test_an_undeletable_boot_log_is_500(linbo_backends):
    _, boot_logs, _, _, _, _ = linbo_backends
    boot_logs.delete_log.side_effect = PermissionError("read-only file system")

    with pytest.raises(HTTPException) as error:
        linbo.delete_boot_log("pc100.log", None)

    assert error.value.status_code == 500


def test_delete_log_value_error_maps_to_400(linbo_backends):
    _, boot_logs, _, _, _, _ = linbo_backends
    boot_logs.delete_log.side_effect = ValueError("Unsafe filename: ../../etc/shadow")

    with pytest.raises(HTTPException) as error:
        linbo.delete_boot_log("../../etc/shadow", None)

    assert error.value.status_code == 400


# ── The traversal guard itself, unmocked ───────────────────────────


@pytest.mark.parametrize(
    "filename",
    ["../shadow", "../../etc/shadow", "sub/pc100.log", "/etc/shadow", "pc100.log;id"],
)
def test_reading_never_escapes_the_boot_log_directory(real_boot_logs, filename):
    _, secret = real_boot_logs

    with pytest.raises(HTTPException) as error:
        linbo.read_boot_log(filename, None)

    assert error.value.status_code == 400
    assert secret.read_text().startswith("root:")


@pytest.mark.parametrize(
    "filename",
    ["../shadow", "../../etc/shadow", "sub/pc100.log", "/etc/shadow"],
)
def test_deleting_never_escapes_the_boot_log_directory(real_boot_logs, filename):
    _, secret = real_boot_logs

    with pytest.raises(HTTPException) as error:
        linbo.delete_boot_log(filename, None)

    assert error.value.status_code == 400
    assert secret.exists()


def test_a_legitimate_boot_log_name_passes_the_traversal_guard(real_boot_logs):
    # Without this the guard could degenerate to "reject everything" and the two
    # tests above would still pass.
    log_dir, _ = real_boot_logs

    assert linbo.read_boot_log("pc100.log", None).body == b"sync finished"
    assert linbo.delete_boot_log("pc100.log", None) == {
        "filename": "pc100.log",
        "status": "deleted",
    }
    assert not (log_dir / "pc100.log").exists()
