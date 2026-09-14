"""
Tests for the VDI config of a LINBO group: GET/PUT/DELETE
/linbo/startconfs/{group_id}/vdi.
"""

from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from routers_v1 import linbo
from routers_v1.body_schemas import LinboVdiConfigBody
from security import RoleChecker


CONFIG = {
    "activated": True,
    "name": "vdi-master",
    "ostype": "l26",
    "cores": 4,
    "memory": 4096,
    "vmids": [101, 102],
}

VDI_ROUTES = {
    ("GET", "/linbo/startconfs/{group_id}/vdi"),
    ("PUT", "/linbo/startconfs/{group_id}/vdi"),
    ("DELETE", "/linbo/startconfs/{group_id}/vdi"),
}


@pytest.fixture
def manager(monkeypatch):
    instance = Mock()
    monkeypatch.setattr(linbo, "LinboConfigManager", Mock(return_value=instance))
    return instance


def test_vdi_routes_are_global_admin_only():
    """
    Same access as the start.conf routes they sit next to. Opening the LINBO
    routes to school admins is issue #37's subject, not this endpoint's.
    """

    routes = [
        route
        for route in linbo.router.routes
        for method in route.methods
        if (method, route.path) in VDI_ROUTES
    ]
    assert len(routes) == len(VDI_ROUTES)

    for route in routes:
        checkers = [
            dependency.call
            for dependency in route.dependant.dependencies
            if isinstance(dependency.call, RoleChecker)
        ]
        assert len(checkers) == 1
        assert checkers[0].roles == ["globaladministrator"]


# ── GET ──────────────────────────────────────────────────────────────────────


def test_get_returns_the_parsed_config(manager):
    manager.read_vdi_config.return_value = CONFIG

    assert linbo.get_startconf_vdi("win11", None) == CONFIG
    manager.read_vdi_config.assert_called_once_with("win11")


def test_get_404s_when_the_group_has_no_vdi_config(manager):
    manager.read_vdi_config.side_effect = FileNotFoundError("not found")

    with pytest.raises(HTTPException) as e:
        linbo.get_startconf_vdi("win11", None)
    assert e.value.status_code == 404


def test_get_400s_on_an_invalid_group_id(manager):
    manager.read_vdi_config.side_effect = ValueError("Invalid linbo_conf name")

    with pytest.raises(HTTPException) as e:
        linbo.get_startconf_vdi("../../etc/passwd", None)
    assert e.value.status_code == 400


# ── PUT ──────────────────────────────────────────────────────────────────────


def test_put_writes_the_config(manager):
    result = linbo.write_startconf_vdi("win11", LinboVdiConfigBody(**CONFIG), None)

    manager.write_vdi_config.assert_called_once_with("win11", CONFIG)
    assert result == {"id": "win11", "status": "ok"}


def test_put_does_not_invent_null_fields(manager):
    """
    A field the client left out must not land in the file as a null: the body
    model declares every field optional, so model_dump() would otherwise write
    thirteen nulls for a request that only flips `activated`.
    """

    linbo.write_startconf_vdi("win11", LinboVdiConfigBody(activated=False), None)

    _, written = manager.write_vdi_config.call_args[0]
    assert written == {"activated": False}


def test_put_keeps_unknown_fields(manager):
    """
    edulution-linbo-vdi owns this file's schema: a field it adds later has to
    survive the round trip instead of being dropped by the API.
    """

    body = LinboVdiConfigBody(**CONFIG, some_future_field="keep me")

    linbo.write_startconf_vdi("win11", body, None)

    _, written = manager.write_vdi_config.call_args[0]
    assert written["some_future_field"] == "keep me"


def test_put_400s_on_an_invalid_group_id(manager):
    manager.write_vdi_config.side_effect = ValueError("Invalid linbo_conf name")

    with pytest.raises(HTTPException) as e:
        linbo.write_startconf_vdi("../../etc/passwd", LinboVdiConfigBody(**CONFIG), None)
    assert e.value.status_code == 400


# ── DELETE ───────────────────────────────────────────────────────────────────


def test_delete_removes_the_config(manager):
    result = linbo.delete_startconf_vdi("win11", None)

    manager.delete_vdi_config.assert_called_once_with("win11")
    assert result == {"id": "win11", "status": "deleted"}


def test_delete_404s_when_the_group_has_no_vdi_config(manager):
    manager.delete_vdi_config.side_effect = FileNotFoundError("not found")

    with pytest.raises(HTTPException) as e:
        linbo.delete_startconf_vdi("win11", None)
    assert e.value.status_code == 404


def test_delete_400s_on_an_invalid_group_id(manager):
    manager.delete_vdi_config.side_effect = ValueError("Invalid linbo_conf name")

    with pytest.raises(HTTPException) as e:
        linbo.delete_startconf_vdi("../etc/passwd", None)
    assert e.value.status_code == 400
