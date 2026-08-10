from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from routers_v1 import linbo
from routers_v1.body_schemas import LinboImageExtrasBody, LinboImageNameBody


BACKUP_TIMESTAMP = "202601271107"
BACKUP_DATE = "27/01/2026 11:07"


class FakeImageGroup:
    """
    Stands in for LinboImageGroup with real attributes rather than a Mock,
    because a Mock invents any attribute that is asked of it and would hide the
    case below: LinboImageGroup.load() returns early when an image's .info
    cannot be read, leaving base None, error set — and diff_image never
    assigned at all.
    """

    def __init__(self, name="win11", backups=None, diff=True, usable=True):
        self.name = name
        self.backups = backups if backups is not None else {}
        if usable:
            self.base = object()
            self.error = None
            self.diff_image = object() if diff else None
        else:
            self.base = None
            self.error = "missing .info"

    def to_dict(self):
        if self.base is None:
            return {"name": self.name, "error": self.error}
        return {"name": self.name}


def make_group(name="win11", backups=None, diff=True, usable=True):
    return FakeImageGroup(name=name, backups=backups, diff=diff, usable=usable)


@pytest.fixture
def manager(monkeypatch):
    """
    Patch the manager class so the endpoints operate on groups we control,
    and accept every name so the tests that are not about validation are not
    coupled to NameChecker's pattern.
    """

    instance = Mock()
    instance.groups = {}
    monkeypatch.setattr(linbo, "LinboImageManager", Mock(return_value=instance))

    checker = Mock()
    checker.check_linbo_image_name.return_value = True
    monkeypatch.setattr(linbo, "name_checker", checker)

    monkeypatch.setattr(linbo, "timestamp2date", lambda ts: BACKUP_DATE)
    return instance


def test_list_images_reports_every_group(manager):
    manager.groups = {"win11": make_group("win11"), "ubuntu": make_group("ubuntu")}

    result = linbo.list_images(None)

    assert result["total"] == 2
    assert {image["name"] for image in result["images"]} == {"win11", "ubuntu"}


def test_delete_image_delegates_to_the_manager(manager):
    manager.groups = {"win11": make_group()}

    result = linbo.delete_image("win11", None)

    manager.delete.assert_called_once_with("win11")
    assert result == {"image": "win11", "status": "deleted"}


def test_delete_image_404s_on_an_unknown_image(manager):
    manager.groups = {}

    with pytest.raises(HTTPException) as error:
        linbo.delete_image("nope", None)

    assert error.value.status_code == 404
    manager.delete.assert_not_called()


def test_delete_image_400s_on_an_invalid_name(manager, monkeypatch):
    checker = Mock()
    checker.check_linbo_image_name.return_value = False
    monkeypatch.setattr(linbo, "name_checker", checker)
    manager.groups = {"win11": make_group()}

    with pytest.raises(HTTPException) as error:
        linbo.delete_image("../../etc", None)

    assert error.value.status_code == 400
    manager.delete.assert_not_called()


def test_delete_diff_404s_when_there_is_no_differential_image(manager):
    manager.groups = {"win11": make_group(diff=False)}

    with pytest.raises(HTTPException) as error:
        linbo.delete_image_diff("win11", None)

    assert error.value.status_code == 404
    manager.delete.assert_not_called()


def test_delete_diff_passes_the_diff_flag(manager):
    manager.groups = {"win11": make_group(diff=True)}

    linbo.delete_image_diff("win11", None)

    manager.delete.assert_called_once_with("win11", diff=True)


def test_delete_backup_converts_the_timestamp_to_the_display_date(manager):
    manager.groups = {"win11": make_group(backups={BACKUP_DATE: Mock()})}

    result = linbo.delete_image_backup("win11", BACKUP_TIMESTAMP, None)

    manager.delete.assert_called_once_with("win11", date=BACKUP_DATE)
    assert result["backup"] == BACKUP_TIMESTAMP


def test_delete_backup_404s_on_an_unknown_backup(manager):
    manager.groups = {"win11": make_group(backups={})}

    with pytest.raises(HTTPException) as error:
        linbo.delete_image_backup("win11", BACKUP_TIMESTAMP, None)

    assert error.value.status_code == 404
    manager.delete.assert_not_called()


def test_delete_backup_400s_on_a_malformed_timestamp(manager, monkeypatch):
    def reject(timestamp):
        raise ValueError("bad timestamp")

    monkeypatch.setattr(linbo, "timestamp2date", reject)
    manager.groups = {"win11": make_group(backups={BACKUP_DATE: Mock()})}

    with pytest.raises(HTTPException) as error:
        linbo.delete_image_backup("win11", "not-a-timestamp", None)

    assert error.value.status_code == 400
    manager.delete.assert_not_called()


def test_restore_backup_delegates_to_the_manager(manager):
    manager.groups = {"win11": make_group(backups={BACKUP_DATE: Mock()})}

    result = linbo.restore_image_backup("win11", BACKUP_TIMESTAMP, None)

    manager.restore.assert_called_once_with("win11", BACKUP_DATE)
    assert result["status"] == "restored"


def test_rename_delegates_to_the_manager(manager):
    manager.groups = {"win11": make_group()}

    result = linbo.rename_image("win11", LinboImageNameBody(new_name="win11-2026"), None)

    manager.rename.assert_called_once_with("win11", "win11-2026")
    assert result == {"image": "win11-2026", "previousName": "win11", "status": "renamed"}


def test_rename_409s_when_the_target_name_is_taken(manager):
    manager.groups = {"win11": make_group(), "ubuntu": make_group("ubuntu")}

    with pytest.raises(HTTPException) as error:
        linbo.rename_image("win11", LinboImageNameBody(new_name="ubuntu"), None)

    assert error.value.status_code == 409
    manager.rename.assert_not_called()


def test_rename_400s_on_an_invalid_target_name(manager, monkeypatch):
    checker = Mock()
    checker.check_linbo_image_name.side_effect = [True, False]
    monkeypatch.setattr(linbo, "name_checker", checker)
    manager.groups = {"win11": make_group()}

    with pytest.raises(HTTPException) as error:
        linbo.rename_image("win11", LinboImageNameBody(new_name="../evil"), None)

    assert error.value.status_code == 400
    manager.rename.assert_not_called()


def test_duplicate_delegates_to_the_manager(manager):
    manager.groups = {"win11": make_group()}

    result = linbo.duplicate_image("win11", LinboImageNameBody(new_name="win11-copy"), None)

    manager.duplicate.assert_called_once_with("win11", "win11-copy")
    assert result["sourceImage"] == "win11"


def test_duplicate_maps_image_exists_error_to_409(manager):
    manager.groups = {"win11": make_group()}
    manager.duplicate.side_effect = linbo.ImageExistsError("/srv/linbo/images/win11-copy")

    with pytest.raises(HTTPException) as error:
        linbo.duplicate_image("win11", LinboImageNameBody(new_name="win11-copy"), None)

    assert error.value.status_code == 409


def test_operations_map_runtime_error_to_409(manager):
    manager.groups = {"win11": make_group()}
    manager.delete.side_effect = RuntimeError("Cannot delete image group win11: missing .info")

    with pytest.raises(HTTPException) as error:
        linbo.delete_image("win11", None)

    assert error.value.status_code == 409


def test_operations_map_an_unreadable_info_to_500(manager):
    """
    rename and duplicate re-read the .info they rewrote; IncompleteImageInfoError
    is a ValueError and would otherwise escape every handler as an opaque 500.
    """

    manager.groups = {"win11": make_group()}
    manager.rename.side_effect = linbo.IncompleteImageInfoError(
        "/srv/linbo/images/win11/win11.qcow2.info", ["timestamp"]
    )

    with pytest.raises(HTTPException) as error:
        linbo.rename_image("win11", LinboImageNameBody(new_name="win12"), None)

    assert error.value.status_code == 500
    assert "no longer readable" in error.value.detail


def test_operations_map_os_error_to_500(manager):
    manager.groups = {"win11": make_group()}
    manager.delete.side_effect = OSError("disk on fire")

    with pytest.raises(HTTPException) as error:
        linbo.delete_image("win11", None)

    assert error.value.status_code == 500


def test_save_extras_forwards_the_body_and_targets_the_base_image(manager):
    manager.groups = {"win11": make_group()}

    result = linbo.save_image_extras(
        "win11",
        LinboImageExtrasBody(info="[OS]\ntimestamp=202601271107", desc="Windows 11", reg="[HKLM]"),
        None,
        False,
        None,
    )

    manager.save_extras.assert_called_once()
    image, data = manager.save_extras.call_args.args
    assert image == "win11"
    assert data["desc"] == "Windows 11"
    assert data["reg"] == "[HKLM]"
    assert data["postsync"] is None
    assert manager.save_extras.call_args.kwargs == {"timestamp": None, "diff": False}
    assert result["status"] == "saved"


def test_save_extras_passes_the_raw_timestamp_not_the_display_date(manager):
    manager.groups = {"win11": make_group(backups={BACKUP_DATE: Mock()})}

    linbo.save_image_extras(
        "win11",
        LinboImageExtrasBody(info="[OS]", desc="a backup"),
        BACKUP_TIMESTAMP,
        False,
        None,
    )

    assert manager.save_extras.call_args.kwargs["timestamp"] == BACKUP_TIMESTAMP


def test_save_extras_rejects_timestamp_and_diff_together(manager):
    manager.groups = {"win11": make_group()}

    with pytest.raises(HTTPException) as error:
        linbo.save_image_extras(
            "win11",
            LinboImageExtrasBody(info="[OS]", desc="x"),
            BACKUP_TIMESTAMP,
            True,
            None,
        )

    assert error.value.status_code == 400
    manager.save_extras.assert_not_called()


def test_save_extras_404s_for_a_diff_that_does_not_exist(manager):
    manager.groups = {"win11": make_group(diff=False)}

    with pytest.raises(HTTPException) as error:
        linbo.save_image_extras("win11", LinboImageExtrasBody(info="[OS]", desc="x"), None, True, None)

    assert error.value.status_code == 404
    manager.save_extras.assert_not_called()


def test_list_backups_keys_by_raw_timestamp(manager):
    backup = Mock()
    backup.timestamp = BACKUP_TIMESTAMP
    backup.to_dict.return_value = {"name": "win11", "timestamp": BACKUP_TIMESTAMP}
    manager.groups = {"win11": make_group(backups={BACKUP_DATE: backup})}

    result = linbo.list_image_backups("win11", None)

    assert result["total"] == 1
    assert BACKUP_TIMESTAMP in result["backups"]


def test_extras_body_refuses_to_drop_the_info_sidecar():
    """
    save_extras deletes any sidecar the body leaves out, and LinboImage.load_info
    raises IncompleteImageInfoError without .info — so a body without info would
    make the image unreadable rather than just edit it.
    """

    with pytest.raises(ValidationError):
        LinboImageExtrasBody(desc="Windows 11")


# An image whose .info cannot be read stays in the listing, flagged, but no
# operation on it can succeed — LinboImageGroup.load() leaves base as None and
# never assigns diff_image. Each of these would otherwise be an opaque 500.


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda: linbo.delete_image("win11", None), id="delete"),
        pytest.param(lambda: linbo.delete_image_diff("win11", None), id="delete-diff"),
        pytest.param(lambda: linbo.list_image_backups("win11", None), id="list-backups"),
        pytest.param(
            lambda: linbo.rename_image("win11", LinboImageNameBody(new_name="win12"), None),
            id="rename",
        ),
        pytest.param(
            lambda: linbo.save_image_extras(
                "win11", LinboImageExtrasBody(info="[OS]"), None, True, None
            ),
            id="extras-diff",
        ),
    ],
)
def test_operations_on_an_unusable_image_409_with_the_reason(manager, call):
    manager.groups = {"win11": make_group(usable=False)}

    with pytest.raises(HTTPException) as error:
        call()

    assert error.value.status_code == 409
    assert "missing .info" in error.value.detail


def test_an_unusable_image_still_appears_in_the_listing(manager):
    manager.groups = {"win11": make_group(usable=False)}

    result = linbo.list_images(None)

    assert result["images"] == [{"name": "win11", "error": "missing .info"}]


# The image management paths share the /images prefix with manifest, download
# and upload. Segment count and literal suffixes keep almost all of them
# disjoint, so registration order does not decide them — with one exception:
# DELETE /images/upload/diff matches both cancel_upload_endpoint (an image
# named "diff") and delete_image_diff (an image named "upload"). Registration
# order settles it in favour of the older route, and the last case below locks
# that in. Asserting on the resolved endpoint rather than on a position in a
# path list keeps the whole check method-aware.

ROUTE_CASES = [
    ("GET", "/linbo/images", "list_images"),
    ("GET", "/linbo/images/manifest", "get_image_manifest"),
    ("GET", "/linbo/images/win11/backups", "list_image_backups"),
    ("GET", "/linbo/images/download/win11/win11.qcow2", "download_image_file"),
    ("GET", "/linbo/images/upload/win11/win11.qcow2/status", "upload_status_endpoint"),
    ("DELETE", "/linbo/images/win11", "delete_image"),
    ("DELETE", "/linbo/images/win11/diff", "delete_image_diff"),
    ("DELETE", "/linbo/images/upload/win11", "cancel_upload_endpoint"),
    ("DELETE", "/linbo/images/win11/backups/202601271107", "delete_image_backup"),
    ("POST", "/linbo/images/win11/rename", "rename_image"),
    ("POST", "/linbo/images/win11/duplicate", "duplicate_image"),
    ("POST", "/linbo/images/win11/backups/202601271107/restore", "restore_image_backup"),
    ("POST", "/linbo/images/upload/win11/complete", "finalize_upload_endpoint"),
    ("PUT", "/linbo/images/win11/extras", "save_image_extras"),
    ("PUT", "/linbo/images/upload/win11/win11.qcow2", "upload_image_file"),
    ("DELETE", "/linbo/images/upload/diff", "cancel_upload_endpoint"),
]


@pytest.mark.parametrize("method,path,expected", ROUTE_CASES)
def test_image_paths_resolve_to_the_intended_endpoint(method, path, expected):
    for route in linbo.router.routes:
        if method in route.methods and route.path_regex.match(path):
            assert route.endpoint.__name__ == expected
            return
    pytest.fail(f"{method} {path} matches no route")
