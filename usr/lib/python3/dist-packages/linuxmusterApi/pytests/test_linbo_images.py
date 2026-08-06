import asyncio
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import HTTPException

from routers_v1 import linbo


def make_request(content_range=None, body=b"chunk-data"):
    request = Mock()
    request.headers = {"content-range": content_range} if content_range else {}
    request.body = AsyncMock(return_value=body)
    return request


@pytest.fixture
def upload_deps(monkeypatch):
    checker = Mock()
    receive = Mock()
    monkeypatch.setattr(linbo, "name_checker", checker)
    monkeypatch.setattr(linbo, "receive_upload_chunk", receive)
    return checker, receive


def test_upload_delegates_to_receive_upload_chunk(upload_deps):
    _, receive = upload_deps
    receive.return_value = {"received": 10, "offset": 10}
    request = make_request(body=b"0123456789")

    result = asyncio.run(linbo.upload_image_file("win11", "win11.qcow2", request, None))

    receive.assert_called_once_with(
        linbo.IMAGES_DIR, "win11", "win11.qcow2", b"0123456789", None
    )
    assert result == {"received": 10, "offset": 10}


def test_upload_parses_content_range_into_offset(upload_deps):
    _, receive = upload_deps
    receive.return_value = {"received": 5, "offset": 105}
    request = make_request(content_range="bytes 100-104/200", body=b"01234")

    asyncio.run(linbo.upload_image_file("win11", "win11.qcow2", request, None))

    receive.assert_called_once_with(
        linbo.IMAGES_DIR, "win11", "win11.qcow2", b"01234", 100
    )


def test_upload_rejects_invalid_content_range(upload_deps):
    _, receive = upload_deps
    request = make_request(content_range="not-a-range")

    with pytest.raises(HTTPException) as error:
        asyncio.run(linbo.upload_image_file("win11", "win11.qcow2", request, None))

    assert error.value.status_code == 400
    receive.assert_not_called()


def test_upload_rejects_unsafe_image_name(upload_deps):
    checker, receive = upload_deps
    checker.check_linbo_image_name.side_effect = ValueError("Unsafe filename: ../etc")
    request = make_request()

    with pytest.raises(HTTPException) as error:
        asyncio.run(linbo.upload_image_file("../etc", "passwd", request, None))

    assert error.value.status_code == 400
    receive.assert_not_called()


def test_upload_wraps_value_error_from_receive_as_400(upload_deps):
    _, receive = upload_deps
    receive.side_effect = ValueError("Offset mismatch: expected 10, got 5")
    request = make_request()

    with pytest.raises(HTTPException) as error:
        asyncio.run(linbo.upload_image_file("win11", "win11.qcow2", request, None))

    assert error.value.status_code == 400


def test_upload_wraps_file_not_found_from_receive_as_404(upload_deps):
    _, receive = upload_deps
    receive.side_effect = FileNotFoundError("Cannot resume upload without an existing staged file")
    request = make_request()

    with pytest.raises(HTTPException) as error:
        asyncio.run(linbo.upload_image_file("win11", "win11.qcow2", request, None))

    assert error.value.status_code == 404
