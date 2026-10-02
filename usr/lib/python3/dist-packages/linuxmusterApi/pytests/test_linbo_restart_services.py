import subprocess
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from routers_v1 import linbo


def test_restart_services_calls_lmntools(monkeypatch):
    services = ['linbo-multicast.service', 'linbo-torrent.service']
    monkeypatch.setattr(linbo, "restart_image_services", Mock(return_value=services))

    assert linbo.restart_services(None) == {"services": services}


def test_restart_services_reports_systemctl_error(monkeypatch):
    error = subprocess.CalledProcessError(1, 'systemctl', stderr="Unit not found.\n")
    monkeypatch.setattr(linbo, "restart_image_services", Mock(side_effect=error))

    with pytest.raises(HTTPException) as e:
        linbo.restart_services(None)

    assert e.value.status_code == 500
    assert "Unit not found." in e.value.detail


def test_restart_services_reports_timeout(monkeypatch):
    error = subprocess.TimeoutExpired('systemctl', 60)
    monkeypatch.setattr(linbo, "restart_image_services", Mock(side_effect=error))

    with pytest.raises(HTTPException) as e:
        linbo.restart_services(None)

    assert e.value.status_code == 500
    assert "timed out" in e.value.detail
