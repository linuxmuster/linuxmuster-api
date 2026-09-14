"""
Tests for a start.conf's backups: GET /linbo/startconfs/{group_id}/backups,
its /restore and its DELETE.
"""

from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from routers_v1 import linbo
from security import RoleChecker


BACKUPS = [
    {"timestamp": 1632669598, "size": 1360, "createdAt": "2021-09-26T15:19:58+00:00"},
    {"timestamp": 1632669588, "size": 1360, "createdAt": "2021-09-26T15:19:48+00:00"},
]

ROUTES = {
    ("GET", "/linbo/startconfs/{group_id}/backups"),
    ("POST", "/linbo/startconfs/{group_id}/backups/{timestamp}/restore"),
    ("DELETE", "/linbo/startconfs/{group_id}/backups/{timestamp}"),
}


@pytest.fixture
def manager(monkeypatch):
    instance = Mock()
    monkeypatch.setattr(linbo, "LinboConfigManager", Mock(return_value=instance))
    return instance


def test_backup_routes_are_open_to_admins():
    routes = [
        route
        for route in linbo.router.routes
        for method in route.methods
        if (method, route.path) in ROUTES
    ]
    assert len(routes) == len(ROUTES)

    for route in routes:
        checkers = [
            dependency.call
            for dependency in route.dependant.dependencies
            if isinstance(dependency.call, RoleChecker)
        ]
        assert len(checkers) == 1
        assert checkers[0].roles == ["globaladministrator", "schooladministrator"]


def test_timestamps_are_taken_as_integers():
    """
    The epoch a backup file is named with, not a free-form path component.
    """

    for route in linbo.router.routes:
        if route.path in (
            "/linbo/startconfs/{group_id}/backups/{timestamp}/restore",
            "/linbo/startconfs/{group_id}/backups/{timestamp}",
        ):
            timestamp = next(p for p in route.dependant.path_params if p.name == "timestamp")
            assert timestamp.field_info.annotation is int


# ── GET ──────────────────────────────────────────────────────────────────────


def test_list_reports_the_backups(manager):
    manager.list_startconf_backups.return_value = BACKUPS

    result = linbo.list_startconf_backups("win11", None)

    manager.list_startconf_backups.assert_called_once_with("win11")
    assert result == {"id": "win11", "backups": BACKUPS, "total": 2}


def test_list_on_a_group_without_backups(manager):
    manager.list_startconf_backups.return_value = []

    assert linbo.list_startconf_backups("win11", None) == {
        "id": "win11",
        "backups": [],
        "total": 0,
    }


def test_list_400s_on_an_invalid_group_id(manager):
    manager.list_startconf_backups.side_effect = ValueError("Invalid linbo_conf name")

    with pytest.raises(HTTPException) as e:
        linbo.list_startconf_backups("../../etc", None)
    assert e.value.status_code == 400


# ── POST …/restore ───────────────────────────────────────────────────────────


def test_restore_delegates_to_the_manager(manager):
    result = linbo.restore_startconf_backup("win11", 1632669598, None)

    manager.restore_startconf_backup.assert_called_once_with("win11", 1632669598)
    assert result == {"id": "win11", "timestamp": 1632669598, "status": "restored"}


def test_restore_404s_on_an_unknown_backup(manager):
    manager.restore_startconf_backup.side_effect = FileNotFoundError("No backup")

    with pytest.raises(HTTPException) as e:
        linbo.restore_startconf_backup("win11", 1632669598, None)
    assert e.value.status_code == 404


def test_restore_400s_on_an_invalid_group_id(manager):
    manager.restore_startconf_backup.side_effect = ValueError("Invalid linbo_conf name")

    with pytest.raises(HTTPException) as e:
        linbo.restore_startconf_backup("../../etc", 1632669598, None)
    assert e.value.status_code == 400


# ── DELETE ───────────────────────────────────────────────────────────────────


def test_delete_delegates_to_the_manager(manager):
    result = linbo.delete_startconf_backup("win11", 1632669598, None)

    manager.delete_startconf_backup.assert_called_once_with("win11", 1632669598)
    assert result == {"id": "win11", "timestamp": 1632669598, "status": "deleted"}


def test_delete_404s_on_an_unknown_backup(manager):
    manager.delete_startconf_backup.side_effect = FileNotFoundError("No backup")

    with pytest.raises(HTTPException) as e:
        linbo.delete_startconf_backup("win11", 1632669598, None)
    assert e.value.status_code == 404


def test_delete_400s_on_an_invalid_group_id(manager):
    manager.delete_startconf_backup.side_effect = ValueError("Invalid linbo_conf name")

    with pytest.raises(HTTPException) as e:
        linbo.delete_startconf_backup("../../etc", 1632669598, None)
    assert e.value.status_code == 400
