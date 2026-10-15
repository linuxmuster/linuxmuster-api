"""
Tests for GET /vdi/groups: display name and OS family of a group.
"""

from unittest.mock import Mock

import pytest

from routers_v1 import vdi
from routers_v1.body_schemas import ConnectionRequest


GROUPS = {
    "general": {"active_groups": ["win11"]},
    "groups": {
        "win11": {"activated": "yes", "ostype": "win11", "cores": 4, "memory": 4096,
                  "minimum_vms": 3, "maximum_vms": 10, "prestarted_vms": 1},
        "cad": {"activated": False, "ostype": "win11", "display_name": "Windows 11 (CAD)"},
    },
}


@pytest.fixture
def groups(monkeypatch):
    monkeypatch.setattr(vdi, "_get_vdi_groups", Mock(return_value=GROUPS))


def test_connection_request_body_is_the_shared_schema():
    """The body model lives in body_schemas; the router must keep importing it."""
    assert vdi.ConnectionRequest is ConnectionRequest
    assert ConnectionRequest(group="win11", user="lehrer01").model_dump() == {"group": "win11", "user": "lehrer01"}


def _by_name(result):
    return {entry["name"]: entry for entry in result}


def test_groups_use_the_library_description_when_available(groups, monkeypatch):
    def describe_group(name, data):
        return {"name": name, "display_name": "Windows 11", "ostype": "win11", "os_family": "windows", "activated": True}

    import types, sys
    fake = types.ModuleType("edulution_linbo_vdi.device_store")
    fake.describe_group = describe_group
    monkeypatch.setitem(sys.modules, "edulution_linbo_vdi.device_store", fake)
    monkeypatch.setitem(sys.modules, "edulution_linbo_vdi", types.ModuleType("edulution_linbo_vdi"))

    result = _by_name(vdi.get_vdi_groups(None))
    assert result["win11"]["display_name"] == "Windows 11"
    assert result["win11"]["os_family"] == "windows"
    assert result["win11"]["activated"] is True
    assert result["cad"]["activated"] is False


def test_groups_fall_back_to_the_group_name_without_the_helper(groups, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "edulution_linbo_vdi.device_store", None)

    result = _by_name(vdi.get_vdi_groups(None))
    assert result["win11"]["display_name"] == "win11"
    assert result["win11"]["os_family"] == ""
    # a display_name in the file is honoured even without the helper
    assert result["cad"]["display_name"] == "Windows 11 (CAD)"
