import configparser
from unittest.mock import Mock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from routers_v1 import devices
from security import AuthenticatedUser, RoleChecker, check_authentication_header


ROLES = [
    "addc",
    "byod",
    "classroom-studentcomputer",
    "classroom-teachercomputer",
    "faculty-teachercomputer",
    "iponly",
    "mobile",
    "printer",
    "router",
    "server",
    "staffcomputer",
    "switch",
    "thinclient",
    "voip",
    "wlan",
]


@pytest.fixture
def sophomorix_ini(monkeypatch):
    ini = Mock()
    ini.computerrole = list(reversed(ROLES))
    monkeypatch.setattr(devices, "SophomorixIni", lambda: ini)
    return ini


def make_client(role="globaladministrator"):
    """The devices router alone, with authentication resolved to one role.

    Calling the handler directly cannot show which route a request reaches, and
    that is the property worth pinning here — /devices/{device} would answer for
    /devices/roles if the two were registered the other way round.

    Only check_authentication_header is overridden, so RoleChecker itself still
    runs. That is what makes the denial cases below real: the equivalent tests
    in test_devices.py go through the live server and never get past
    authentication on a machine without matching credentials.
    """

    app = FastAPI()
    app.include_router(devices.router, prefix="/v1")
    app.dependency_overrides[check_authentication_header] = lambda: AuthenticatedUser(
        dn="",
        user=role,
        role=role,
    )
    return TestClient(app)


@pytest.fixture
def client():
    return make_client()


def test_a_get_on_the_roles_path_reaches_the_roles_handler(sophomorix_ini, client):
    response = client.get("/v1/devices/roles")

    assert response.status_code == 200
    assert response.json() == ROLES


def test_roles_are_returned_sorted(sophomorix_ini):
    assert devices.get_computer_roles(None) == ROLES


def test_roles_follow_the_installation_rather_than_a_fixed_list(sophomorix_ini):
    # The point of the endpoint: a server that defines its own roles gets them,
    # which a hardcoded list in a client could not. Also the assertion that fails
    # if the handler ever stops reading the ini.
    sophomorix_ini.computerrole = ["custom-lab-pc", "addc"]

    assert devices.get_computer_roles(None) == ["addc", "custom-lab-pc"]


def test_roles_are_read_per_request(monkeypatch):
    # Instantiated in the handler, so editing sophomorix.ini does not need an API
    # restart to take effect.
    calls = []

    def _make():
        calls.append(1)
        ini = Mock()
        ini.computerrole = ROLES
        return ini

    monkeypatch.setattr(devices, "SophomorixIni", _make)

    devices.get_computer_roles(None)
    devices.get_computer_roles(None)

    assert len(calls) == 2


@pytest.mark.parametrize(
    "error",
    [
        # ConfigParser.read() ignores a missing or unreadable file; the constructor
        # then reads a section this endpoint never asked for.
        KeyError("ROLE_USER"),
        configparser.MissingSectionHeaderError("sophomorix.ini", 1, "stray = line"),
    ],
)
def test_an_unreadable_sophomorix_ini_names_the_file(monkeypatch, error):
    def _raise():
        raise error

    monkeypatch.setattr(devices, "SophomorixIni", _raise)

    with pytest.raises(HTTPException) as raised:
        devices.get_computer_roles(None)

    assert raised.value.status_code == 500
    assert "sophomorix" in raised.value.detail.lower()
    # The original error is kept: KeyError('ROLE_USER') on its own would send an
    # admin looking at user roles.
    assert repr(error) in raised.value.detail


def test_roles_route_is_registered_before_the_device_path_parameter():
    # Cheap structural companion to the routing test above; on its own it is only
    # a proxy, since it compares path strings and is blind to the method.
    paths = [route.path for route in devices.router.routes]

    assert paths.index("/devices/roles") < paths.index("/devices/{device}")


@pytest.mark.parametrize("role", ["globaladministrator", "schooladministrator"])
def test_roles_are_served_to_administrators(sophomorix_ini, role):
    response = make_client(role).get("/v1/devices/roles")

    assert response.status_code == 200
    assert response.json() == ROLES


@pytest.mark.parametrize("role", ["teacher", "student", "parent", "staff"])
def test_roles_are_denied_to_everyone_else(sophomorix_ini, role):
    response = make_client(role).get("/v1/devices/roles")

    assert response.status_code == 401
    assert response.json()["detail"] == "Permission denied"


def test_roles_route_is_open_to_school_administrators():
    route = next(
        r
        for r in devices.router.routes
        if r.path == "/devices/roles" and "GET" in r.methods
    )
    checkers = [
        dependency.call
        for dependency in route.dependant.dependencies
        if isinstance(dependency.call, RoleChecker)
    ]

    assert len(checkers) == 1
    assert checkers[0].roles == ["globaladministrator", "schooladministrator"]
