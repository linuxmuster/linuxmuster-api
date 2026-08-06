from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from routers_v1 import linbo
from routers_v1.body_schemas import LinboHostScanRequest, LinboWolRequest
from security import RoleChecker


@pytest.fixture
def linbo_backends(monkeypatch):
    devices = Mock()
    boot_logs = Mock()
    scan = Mock(return_value=[])
    wol = Mock(return_value={})
    image_status = Mock(return_value={})

    monkeypatch.setattr(linbo, "Devices", lambda school: devices)
    monkeypatch.setattr(linbo, "LinboBootLogs", lambda: boot_logs)
    monkeypatch.setattr(linbo, "scan_hosts_sync", scan)
    monkeypatch.setattr(linbo, "send_wol_bulk", wol)
    monkeypatch.setattr(linbo, "get_host_image_status", image_status)
    monkeypatch.setattr(linbo, "check_valid_school_or_404", lambda school: school)
    return devices, boot_logs, scan, wol, image_status


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
    for route in linbo.router.routes:
        checkers = [
            dependency.call
            for dependency in route.dependant.dependencies
            if isinstance(dependency.call, RoleChecker)
        ]
        assert len(checkers) == 1, f"{route.path} has {len(checkers)} role checkers"
        assert checkers[0].roles == ["globaladministrator"], route.path


def test_scan_without_macs_probes_every_client(linbo_backends):
    devices, _, scan, _, _ = linbo_backends
    clients = [{"mac": "00:11:22:33:44:55", "ip": "10.0.0.100", "hostname": "pc100"}]
    devices.get_clients.return_value = clients
    scan.return_value = [{"mac": clients[0]["mac"], "online": True}]

    result = linbo.scan_hosts(LinboHostScanRequest(), "default-school", None)

    scan.assert_called_once_with(clients)
    devices.get_hosts_by_macs.assert_not_called()
    assert result["hosts"] == scan.return_value
    assert "scannedAt" in result


def test_scan_with_macs_probes_only_those_hosts(linbo_backends):
    devices, _, scan, _, _ = linbo_backends
    macs = ["00:11:22:33:44:55"]
    hosts = [{"mac": macs[0], "ip": "10.0.0.100", "hostname": "pc100"}]
    devices.get_hosts_by_macs.return_value = hosts

    linbo.scan_hosts(LinboHostScanRequest(macs=macs), "default-school", None)

    devices.get_hosts_by_macs.assert_called_once_with(macs)
    devices.get_clients.assert_not_called()
    scan.assert_called_once_with(hosts)


def test_scan_rejects_more_than_500_macs(linbo_backends):
    _, _, scan, _, _ = linbo_backends
    body = LinboHostScanRequest(macs=[f"00:00:00:00:00:{i:02x}" for i in range(501)])

    with pytest.raises(HTTPException) as error:
        linbo.scan_hosts(body, "default-school", None)

    assert error.value.status_code == 400
    scan.assert_not_called()


def test_scan_without_any_host_is_404(linbo_backends):
    devices, _, scan, _, _ = linbo_backends
    devices.get_clients.return_value = []

    with pytest.raises(HTTPException) as error:
        linbo.scan_hosts(LinboHostScanRequest(), "default-school", None)

    assert error.value.status_code == 404
    scan.assert_not_called()


def test_wol_delegates_with_packet_parameters(linbo_backends):
    _, _, _, wol, _ = linbo_backends
    macs = ["00:11:22:33:44:55"]
    wol.return_value = {"total": 1, "successful": 1, "failed": 0, "results": []}

    body = LinboWolRequest(macs=macs, broadcast="10.0.0.255", port=7, count=5)
    result = linbo.wake_hosts(body, None)

    wol.assert_called_once_with(macs, broadcast="10.0.0.255", port=7, count=5)
    assert result == wol.return_value


def test_wol_without_macs_is_rejected(linbo_backends):
    _, _, _, wol, _ = linbo_backends

    with pytest.raises(HTTPException) as error:
        linbo.wake_hosts(LinboWolRequest(macs=[]), None)

    assert error.value.status_code == 400
    wol.assert_not_called()


def test_wol_rejects_more_than_500_macs(linbo_backends):
    _, _, _, wol, _ = linbo_backends
    body = LinboWolRequest(macs=[f"00:00:00:00:00:{i:02x}" for i in range(501)])

    with pytest.raises(HTTPException) as error:
        linbo.wake_hosts(body, None)

    assert error.value.status_code == 400
    wol.assert_not_called()


def test_image_status_reports_total(linbo_backends):
    _, _, _, _, image_status = linbo_backends
    image_status.return_value = {"pc100": {"lastSync": "2026-03-24T11:42:00.000Z"}}

    result = linbo.hosts_image_status(None)

    assert result == {"hosts": image_status.return_value, "total": 1}


def test_boot_logs_are_listed_with_total(linbo_backends):
    _, boot_logs, _, _, _ = linbo_backends
    boot_logs.list_logs.return_value = [{"filename": "pc100.log", "size": 12}]

    result = linbo.list_boot_logs(None)

    assert result == {"logs": boot_logs.list_logs.return_value, "total": 1}


def test_boot_log_is_returned_as_plain_text(linbo_backends):
    _, boot_logs, _, _, _ = linbo_backends
    boot_logs.read_log.return_value = "sync finished"

    response = linbo.read_boot_log("pc100.log", None)

    boot_logs.read_log.assert_called_once_with("pc100.log")
    assert response.body == b"sync finished"


def test_missing_boot_log_is_404(linbo_backends):
    _, boot_logs, _, _, _ = linbo_backends
    boot_logs.read_log.return_value = None

    with pytest.raises(HTTPException) as error:
        linbo.read_boot_log("nope.log", None)

    assert error.value.status_code == 404


def test_unsafe_boot_log_name_is_400(linbo_backends):
    _, boot_logs, _, _, _ = linbo_backends
    boot_logs.read_log.side_effect = ValueError("Unsafe filename: ../../etc/shadow")

    with pytest.raises(HTTPException) as error:
        linbo.read_boot_log("../../etc/shadow", None)

    assert error.value.status_code == 400


def test_boot_log_deletion_reports_the_filename(linbo_backends):
    _, boot_logs, _, _, _ = linbo_backends
    boot_logs.delete_log.return_value = True

    assert linbo.delete_boot_log("pc100.log", None) == {
        "filename": "pc100.log",
        "status": "deleted",
    }


def test_deleting_a_missing_boot_log_is_404(linbo_backends):
    _, boot_logs, _, _, _ = linbo_backends
    boot_logs.delete_log.return_value = False

    with pytest.raises(HTTPException) as error:
        linbo.delete_boot_log("nope.log", None)

    assert error.value.status_code == 404


def test_unsafe_name_on_delete_is_400(linbo_backends):
    _, boot_logs, _, _, _ = linbo_backends
    boot_logs.delete_log.side_effect = ValueError("Unsafe filename: ../../etc/shadow")

    with pytest.raises(HTTPException) as error:
        linbo.delete_boot_log("../../etc/shadow", None)

    assert error.value.status_code == 400
