from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from routers_v1 import linbo_sync
from routers_v1.body_schemas import LinboRemoteRunBody
from security import RoleChecker
from linuxmusterTools.linbo import LinboRemoteParameterError


def test_routes_require_global_or_school_admin():
    expected = {
        ("POST", "/linbo/sync/run"),
        ("GET", "/linbo/sync/sessions"),
        ("GET", "/linbo/sync/hosts/{hostname}/status"),
    }
    actual = {
        (method, route.path)
        for route in linbo_sync.router.routes
        for method in route.methods
    }
    assert actual == expected

    for route in linbo_sync.router.routes:
        checkers = [
            dependency.call
            for dependency in route.dependant.dependencies
            if isinstance(dependency.call, RoleChecker)
        ]
        assert len(checkers) == 1
        assert checkers[0].roles == ["globaladministrator", "schooladministrator"]


# ── /run ─────────────────────────────────────────────────────────────────


def test_run_delegates_to_linbo_remote(monkeypatch):
    monkeypatch.setattr("utils.checks.lr.getval", lambda *a, **k: ["default-school"])
    remote = Mock()
    remote.run.return_value = {"status": 0, "msg": "ok"}
    monkeypatch.setattr(linbo_sync, "LinboRemote", lambda **kwargs: remote)

    body = LinboRemoteRunBody(cmd="reboot", group="win10")
    who = Mock(school="global")
    result = linbo_sync.run_linbo_remote(body=body, school="default-school", who=who)

    assert result == {"status": 0, "msg": "ok"}


def test_run_raises_400_on_parameter_error(monkeypatch):
    monkeypatch.setattr("utils.checks.lr.getval", lambda *a, **k: ["default-school"])
    remote = Mock()
    remote.run.side_effect = LinboRemoteParameterError("bad group")
    monkeypatch.setattr(linbo_sync, "LinboRemote", lambda **kwargs: remote)

    body = LinboRemoteRunBody(cmd="reboot", group="win10")
    who = Mock(school="global")

    with pytest.raises(HTTPException) as exc_info:
        linbo_sync.run_linbo_remote(body=body, school="default-school", who=who)

    assert exc_info.value.status_code == 400
    assert "bad group" in exc_info.value.detail


def test_run_rejects_too_many_clients(monkeypatch):
    monkeypatch.setattr("utils.checks.lr.getval", lambda *a, **k: ["default-school"])
    body = LinboRemoteRunBody(cmd="reboot", clients=[f"10.0.0.{i}" for i in range(600)])
    who = Mock(school="global")

    with pytest.raises(HTTPException) as exc_info:
        linbo_sync.run_linbo_remote(body=body, school="default-school", who=who)

    assert exc_info.value.status_code == 400


def test_run_passes_none_school_for_default_school(monkeypatch):
    monkeypatch.setattr("utils.checks.lr.getval", lambda *a, **k: ["default-school"])
    captured = {}

    def fake_linbo_remote(**kwargs):
        captured.update(kwargs)
        return Mock(run=Mock(return_value={"status": 0, "msg": ""}))

    monkeypatch.setattr(linbo_sync, "LinboRemote", fake_linbo_remote)

    body = LinboRemoteRunBody(cmd="reboot", group="win10")
    who = Mock(school="global")
    linbo_sync.run_linbo_remote(body=body, school="default-school", who=who)

    assert captured["school"] is None


def test_run_passes_school_when_not_default(monkeypatch):
    monkeypatch.setattr("utils.checks.lr.getval", lambda *a, **k: ["lehrer"])
    captured = {}

    def fake_linbo_remote(**kwargs):
        captured.update(kwargs)
        return Mock(run=Mock(return_value={"status": 0, "msg": ""}))

    monkeypatch.setattr(linbo_sync, "LinboRemote", fake_linbo_remote)

    body = LinboRemoteRunBody(cmd="reboot", group="win10")
    who = Mock(school="global")
    linbo_sync.run_linbo_remote(body=body, school="lehrer", who=who)

    assert captured["school"] == "lehrer"


def test_run_defaults_to_who_school_for_school_admin(monkeypatch):
    # require_school doesn't call check_valid_school_or_404 on this branch:
    # a school-administrator's own school is trusted, no LDAP call needed.
    captured = {}

    def fake_linbo_remote(**kwargs):
        captured.update(kwargs)
        return Mock(run=Mock(return_value={"status": 0, "msg": ""}))

    monkeypatch.setattr(linbo_sync, "LinboRemote", fake_linbo_remote)

    body = LinboRemoteRunBody(cmd="reboot", group="win10")
    who = Mock(school="lehrer")
    linbo_sync.run_linbo_remote(body=body, school="", who=who)

    assert captured["school"] == "lehrer"


def test_run_school_admin_cannot_target_another_school():
    body = LinboRemoteRunBody(cmd="reboot", group="win10")
    who = Mock(school="lehrer")

    with pytest.raises(HTTPException) as exc_info:
        linbo_sync.run_linbo_remote(body=body, school="other-school", who=who)

    assert exc_info.value.status_code == 403


def test_run_global_admin_must_specify_school():
    body = LinboRemoteRunBody(cmd="reboot", group="win10")
    who = Mock(school="global")

    with pytest.raises(HTTPException) as exc_info:
        linbo_sync.run_linbo_remote(body=body, school="", who=who)

    assert exc_info.value.status_code == 400


# ── /sessions ────────────────────────────────────────────────────────────


def test_get_running_sessions_global_admin_sees_everything(monkeypatch):
    monkeypatch.setattr(
        linbo_sync,
        "list_running_sessions",
        lambda: [{"hostname": "pc001"}, {"hostname": "lehrer-pc002"}],
    )

    who = Mock(school="global")
    result = linbo_sync.get_running_sessions(who=who)

    assert result == {"sessions": [{"hostname": "pc001"}, {"hostname": "lehrer-pc002"}]}


def test_get_running_sessions_school_admin_is_filtered(monkeypatch):
    monkeypatch.setattr(
        linbo_sync,
        "list_running_sessions",
        lambda: [{"hostname": "pc001"}, {"hostname": "lehrer-pc002"}],
    )
    devices = Mock()
    devices.devices = [{"hostname": "pc002"}]
    monkeypatch.setattr(linbo_sync, "Devices", lambda school: devices)

    who = Mock(school="lehrer")
    result = linbo_sync.get_running_sessions(who=who)

    assert result == {"sessions": [{"hostname": "lehrer-pc002"}]}


# ── /hosts/{hostname}/status ──────────────────────────────────────────────


def test_get_host_status_global_admin_unrestricted(monkeypatch):
    monkeypatch.setattr(linbo_sync, "classify_host", lambda hostname: "Linbo")

    who = Mock(school="global")
    result = linbo_sync.get_host_status("any-host", who=who)

    assert result == {"hostname": "any-host", "status": "Linbo"}


def test_get_host_status_school_admin_own_host(monkeypatch):
    monkeypatch.setattr(linbo_sync, "classify_host", lambda hostname: "Linbo")
    devices = Mock()
    devices.devices = [{"hostname": "pc002"}]
    monkeypatch.setattr(linbo_sync, "Devices", lambda school: devices)

    who = Mock(school="lehrer")
    result = linbo_sync.get_host_status("lehrer-pc002", who=who)

    assert result == {"hostname": "lehrer-pc002", "status": "Linbo"}


def test_get_host_status_school_admin_other_school_is_404(monkeypatch):
    devices = Mock()
    devices.devices = [{"hostname": "pc002"}]
    monkeypatch.setattr(linbo_sync, "Devices", lambda school: devices)

    who = Mock(school="lehrer")

    with pytest.raises(HTTPException) as exc_info:
        linbo_sync.get_host_status("other-school-pc099", who=who)

    assert exc_info.value.status_code == 404
