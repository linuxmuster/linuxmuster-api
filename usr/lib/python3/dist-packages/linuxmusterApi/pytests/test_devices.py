import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]

_need_device = pytest.mark.skipif(DEVICE == 'UNCONFIGURED', reason="DEVICE not set in credentials.py")


class TestDevices:
    def test_get_devices_list_ga(self):
        r = client.get(f"{BASE_URL}/devices/list/{SCHOOL}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_devices_list_sa(self):
        r = client.get(f"{BASE_URL}/devices/list/{SCHOOL}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_devices_list_denied(self, user):
        r = client.get(f"{BASE_URL}/devices/list/{SCHOOL}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_devices_list_sa_other_school_forbidden(self):
        r = client.get(f"{BASE_URL}/devices/list/other-school", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 403

    @_need_device
    def test_get_device_ga(self):
        r = client.get(f"{BASE_URL}/devices/{DEVICE}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == DEVICE

    @_need_device
    def test_get_device_sa(self):
        r = client.get(f"{BASE_URL}/devices/{DEVICE}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_device_denied(self, user):
        r = client.get(f"{BASE_URL}/devices/{DEVICE}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_patch_device_denied(self, user):
        r = client.patch(
            f"{BASE_URL}/devices/{DEVICE}",
            headers={"X-API-KEY": user.jwt},
            json={}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_post_devices_list_denied(self, user):
        r = client.post(
            f"{BASE_URL}/devices/list/{SCHOOL}",
            headers={"X-API-KEY": user.jwt},
            json={"data": []}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_post_devices_list_sa_other_school_forbidden(self):
        r = client.post(
            f"{BASE_URL}/devices/list/other-school",
            headers={"X-API-KEY": SCHOOLADMIN.jwt},
            json={"data": []}
        )
        assert r.status_code == 403

    @pytest.mark.parametrize("user", USERS[2:])
    def test_import_devices_denied(self, user):
        r = client.get(f"{BASE_URL}/devices/list/{SCHOOL}/import-devices", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_import_devices_sa_other_school_forbidden(self):
        r = client.get(f"{BASE_URL}/devices/list/other-school/import-devices", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 403

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_device_roles_denied(self, user):
        r = client.get(f"{BASE_URL}/devices/roles", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]
