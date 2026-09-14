"""
Tests for the two read-only routes over what the server already holds in
/srv/linbo: GET /linbo/iso and GET /linbo/examples[/{name}].
"""

from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from routers_v1 import linbo
from security import RoleChecker


EXAMPLES = [
    {"name": "image.postsync", "type": "postsync", "size": 13, "updatedAt": None},
    {"name": "start.conf.ubuntu", "type": "config", "size": 23, "updatedAt": None},
]

ROUTES = {
    ("GET", "/linbo/iso"),
    ("GET", "/linbo/examples"),
    ("GET", "/linbo/examples/{name}"),
}


@pytest.fixture
def manager(monkeypatch):
    instance = Mock()
    monkeypatch.setattr(linbo, "LinboConfigManager", Mock(return_value=instance))
    return instance


@pytest.fixture
def linbo_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(linbo, "LINBO_DIR", tmp_path)
    return tmp_path


def test_routes_are_open_to_admins():
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


# ── GET /linbo/iso ───────────────────────────────────────────────────────────


def test_iso_is_served_as_a_resumable_file(linbo_dir):
    (linbo_dir / "linbo.iso").write_bytes(b"ISO")

    response = linbo.download_linbo_iso(None)

    assert Path(response.path) == linbo_dir / "linbo.iso"
    assert response.filename == "linbo.iso"
    # Starlette's FileResponse answers Range/If-Range itself, which is what
    # makes a several-hundred-megabyte download resumable.
    assert response.headers["accept-ranges"] == "bytes"


def test_iso_404s_when_the_server_has_none(linbo_dir):
    with pytest.raises(HTTPException) as e:
        linbo.download_linbo_iso(None)
    assert e.value.status_code == 404


def test_iso_404s_rather_than_serving_a_directory(linbo_dir):
    (linbo_dir / "linbo.iso").mkdir()

    with pytest.raises(HTTPException) as e:
        linbo.download_linbo_iso(None)
    assert e.value.status_code == 404


# ── GET /linbo/examples ──────────────────────────────────────────────────────


def test_list_examples_reports_the_manager_listing(manager):
    manager.list_examples.return_value = EXAMPLES

    assert linbo.list_linbo_examples(None) == {"examples": EXAMPLES, "total": 2}


def test_list_examples_on_a_server_without_them(manager):
    manager.list_examples.return_value = []

    assert linbo.list_linbo_examples(None) == {"examples": [], "total": 0}


# ── GET /linbo/examples/{name} ───────────────────────────────────────────────


def test_get_example_returns_its_content(manager):
    manager.read_example.return_value = "[LINBO]\nGroup = ubuntu\n"

    result = linbo.get_linbo_example("start.conf.ubuntu", None)

    manager.read_example.assert_called_once_with("start.conf.ubuntu")
    assert result == {"name": "start.conf.ubuntu", "content": "[LINBO]\nGroup = ubuntu\n"}


def test_get_example_404s_on_a_name_the_listing_does_not_report(manager):
    """
    The whitelist lives in the manager: a path, or a file of that directory
    which is not an example, comes back as a 404 rather than a read.
    """

    manager.read_example.side_effect = FileNotFoundError("Example ../../etc/passwd not found.")

    with pytest.raises(HTTPException) as e:
        linbo.get_linbo_example("../../etc/passwd", None)
    assert e.value.status_code == 404
