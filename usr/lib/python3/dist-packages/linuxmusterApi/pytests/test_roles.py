import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]


class TestRoles:
    def test_get_roles_ga(self):
        r = client.get(f"{BASE_URL}/roles/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_roles_sa(self):
        r = client.get(f"{BASE_URL}/roles/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_roles_denied(self, user):
        r = client.get(f"{BASE_URL}/roles/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_roles_teachers_ga(self):
        r = client.get(f"{BASE_URL}/roles/teachers", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_roles_teachers_sa(self):
        r = client.get(f"{BASE_URL}/roles/teachers", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_roles_teachers_denied(self, user):
        r = client.get(f"{BASE_URL}/roles/teachers", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]


class TestServer:
    def test_get_lmnversion_ga(self):
        r = client.get(f"{BASE_URL}/server/lmnversion", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)
        assert len(data) > 0

    def test_get_lmnversion_sa(self):
        r = client.get(f"{BASE_URL}/server/lmnversion", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_lmnversion_denied(self, user):
        r = client.get(f"{BASE_URL}/server/lmnversion", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]
