from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from routers_v1 import linbo_drivers
from routers_v1.body_schemas import (
    LinboDriverImageAssignment,
    LinboDriverMatchUpdate,
    LinboDriverProfileCreate,
)
from security import RoleChecker


@pytest.fixture
def managers(monkeypatch):
    drivers = Mock()
    images = Mock()
    inventory = Mock()

    monkeypatch.setattr(linbo_drivers, "LinboDriverManager", lambda: drivers)
    monkeypatch.setattr(linbo_drivers, "LinboImageManager", lambda: images)
    monkeypatch.setattr(
        linbo_drivers,
        "LinboHardwareInventoryManager",
        lambda school: inventory,
    )
    monkeypatch.setattr(
        linbo_drivers,
        "check_valid_school_or_404",
        lambda school: school,
    )
    return drivers, images, inventory


def test_routes_are_global_admin_only():
    expected = {
        ("GET", "/linbo/drivers/inventory"),
        ("GET", "/linbo/drivers/inventory/{hostname}"),
        ("GET", "/linbo/drivers/profiles"),
        ("POST", "/linbo/drivers/profiles"),
        ("GET", "/linbo/drivers/profiles/{profile_name}"),
        ("PUT", "/linbo/drivers/profiles/{profile_name}/match"),
        ("GET", "/linbo/drivers/profiles/{profile_name}/image"),
        ("PUT", "/linbo/drivers/profiles/{profile_name}/image"),
        ("DELETE", "/linbo/drivers/profiles/{profile_name}/image"),
        ("DELETE", "/linbo/drivers/profiles/{profile_name}"),
    }
    actual = {
        (method, route.path)
        for route in linbo_drivers.router.routes
        for method in route.methods
    }
    assert actual == expected

    for route in linbo_drivers.router.routes:
        checkers = [
            dependency.call
            for dependency in route.dependant.dependencies
            if isinstance(dependency.call, RoleChecker)
        ]
        assert len(checkers) == 1
        assert checkers[0].roles == ["globaladministrator"]


def test_inventory_delegates_to_inventory_manager(managers):
    _, _, inventory = managers
    expected = [{"hostname": "client01"}]
    inventory.list.return_value = expected
    inventory.get.return_value = expected[0]

    assert linbo_drivers.list_driver_inventory("default-school", None) == expected
    assert (
        linbo_drivers.get_driver_inventory(
            "client01",
            "default-school",
            None,
        )
        == expected[0]
    )


def test_profile_crud_delegates_to_driver_manager(managers):
    drivers, _, _ = managers
    profile = {
        "name": "lenovo-21l4",
        "path": "/srv/linbo/drivers/lenovo-21l4",
        "matchConf": {"vendor": "LENOVO", "product": "21L4"},
    }
    drivers.create_profile.return_value = profile
    drivers.get_profile.return_value = profile
    drivers.list_profiles.return_value = [profile]
    drivers.update_match.return_value = profile
    drivers.delete_profile.return_value = True

    listed = linbo_drivers.list_driver_profiles(None)
    fetched = linbo_drivers.get_driver_profile("lenovo-21l4", None)
    created = linbo_drivers.create_driver_profile(
        LinboDriverProfileCreate(
            name="lenovo-21l4",
            vendor="LENOVO",
            product="21L4",
        ),
        None,
    )
    updated = linbo_drivers.update_driver_profile_match(
        "lenovo-21l4",
        LinboDriverMatchUpdate(vendor="LENOVO", product="21L4"),
        None,
    )
    deleted = linbo_drivers.delete_driver_profile("lenovo-21l4", None)

    drivers.create_profile.assert_called_once_with(
        "lenovo-21l4",
        "LENOVO",
        "21L4",
    )
    drivers.update_match.assert_called_once_with(
        "lenovo-21l4",
        "LENOVO",
        "21L4",
    )
    assert "path" not in created
    assert listed == [created]
    assert fetched == created
    assert updated == created
    assert deleted == {"deleted": True, "name": "lenovo-21l4"}


def test_image_assignment_delegates_to_image_manager(managers):
    _, images, _ = managers
    expected = {"profile": "lenovo-21l4", "image": "win11"}
    images.get_driver_profile_image.return_value = "win11"
    images.assign_driver_profile.return_value = expected
    images.unassign_driver_profile.return_value = {
        "profile": "lenovo-21l4",
        "image": None,
    }

    current = linbo_drivers.get_driver_profile_image("lenovo-21l4", None)
    result = linbo_drivers.assign_driver_profile_image(
        "lenovo-21l4",
        LinboDriverImageAssignment(image="win11"),
        None,
    )
    removed = linbo_drivers.unassign_driver_profile_image(
        "lenovo-21l4",
        None,
    )

    assert current == expected
    images.assign_driver_profile.assert_called_once_with(
        "lenovo-21l4",
        "win11",
    )
    assert result == expected
    assert removed == {"profile": "lenovo-21l4", "image": None}


def test_missing_profile_returns_not_found(managers):
    drivers, _, _ = managers
    drivers.get_profile.return_value = None
    drivers.delete_profile.return_value = False

    with pytest.raises(HTTPException) as missing_get:
        linbo_drivers.get_driver_profile("missing", None)
    with pytest.raises(HTTPException) as missing_delete:
        linbo_drivers.delete_driver_profile("missing", None)

    assert missing_get.value.status_code == 404
    assert missing_delete.value.status_code == 404


@pytest.mark.parametrize(
    "error,status_code",
    [
        (linbo_drivers.DriverProfileExistsError("profile"), 409),
        (PermissionError("unmanaged driverpostsync"), 409),
        (FileNotFoundError("missing profile"), 404),
        (ValueError("invalid profile"), 400),
    ],
)
def test_expected_tools_errors_are_mapped(error, status_code):
    with pytest.raises(HTTPException) as raised:
        linbo_drivers._raise_driver_http_error(error)

    assert raised.value.status_code == status_code
    assert raised.value.detail == str(error)
