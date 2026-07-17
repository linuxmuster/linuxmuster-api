"""Focused unit tests for finalizing LINBO image uploads."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_API_DIST_PACKAGES = _REPOSITORY_ROOT / "usr/lib/python3/dist-packages"
_API_PACKAGE = _API_DIST_PACKAGES / "linuxmusterApi"
sys.path[:0] = [str(_API_DIST_PACKAGES), str(_API_PACKAGE)]


_check_output = subprocess.check_output


def _check_output_without_local_samba_config(command, *args, **kwargs):
    """Keep module imports independent of a local Samba installation."""

    if command == ["/usr/bin/net", "conf", "list"]:
        return b""
    return _check_output(command, *args, **kwargs)


with patch(
    "subprocess.check_output",
    side_effect=_check_output_without_local_samba_config,
):
    from linuxmusterApi.routers_v1 import linbo


def _raise_on_finalize(error):
    def finalize(_images_dir, _image_name):
        raise error

    return finalize


def test_finalize_upload_maps_foreign_hook_to_conflict(monkeypatch):
    error = linbo.DriverHookOwnershipError("existing hook is not managed")
    monkeypatch.setattr(linbo, "finalize_upload", _raise_on_finalize(error))

    with pytest.raises(HTTPException) as exception:
        linbo.finalize_upload_endpoint("win11", who=None)

    assert exception.value.status_code == 409
    assert exception.value.detail == "existing hook is not managed"


def test_finalize_upload_hides_storage_path(monkeypatch):
    protected_path = "/srv/linbo/images/win11/private-target"
    error = linbo.StorageSecurityError(f"unsafe path: {protected_path}")
    monkeypatch.setattr(linbo, "finalize_upload", _raise_on_finalize(error))

    with pytest.raises(HTTPException) as exception:
        linbo.finalize_upload_endpoint("win11", who=None)

    assert exception.value.status_code == 500
    assert exception.value.detail == "LINBO driver storage safety check failed"
    assert protected_path not in exception.value.detail


def test_finalize_upload_maps_transaction_ownership_cause_to_conflict(monkeypatch):
    cause = linbo.DriverHookOwnershipError("existing hook is not managed")
    error = linbo.DriverHookTransactionError(
        "image upload transaction failed",
        cause=cause,
    )
    monkeypatch.setattr(linbo, "finalize_upload", _raise_on_finalize(error))

    with pytest.raises(HTTPException) as exception:
        linbo.finalize_upload_endpoint("win11", who=None)

    assert exception.value.status_code == 409
    assert exception.value.detail == "existing hook is not managed"
