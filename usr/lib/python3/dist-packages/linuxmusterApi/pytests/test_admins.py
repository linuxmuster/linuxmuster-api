import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]


class TestGlobalAdministrators:
    def test_get_globaladmins_ga(self):
        r = client.get(f"{BASE_URL}/globaladministrators/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) > 0

    @pytest.mark.parametrize("user", USERS[1:])
    def test_get_globaladmins_denied(self, user):
        r = client.get(f"{BASE_URL}/globaladministrators/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_globaladmin_ga(self):
        r = client.get(f"{BASE_URL}/globaladministrators/{GLOBALADMIN.cn}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == GLOBALADMIN.cn

    @pytest.mark.parametrize("user", USERS[1:])
    def test_get_globaladmin_denied(self, user):
        r = client.get(f"{BASE_URL}/globaladministrators/{GLOBALADMIN.cn}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]


class TestSchoolAdministrators:
    def test_get_schooladmins_ga(self):
        r = client.get(f"{BASE_URL}/schooladministrators/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_schooladmins_sa(self):
        r = client.get(f"{BASE_URL}/schooladministrators/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_schooladmins_denied(self, user):
        r = client.get(f"{BASE_URL}/schooladministrators/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_schooladmin_ga(self):
        r = client.get(f"{BASE_URL}/schooladministrators/{SCHOOLADMIN.cn}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == SCHOOLADMIN.cn

    def test_get_schooladmin_sa(self):
        r = client.get(f"{BASE_URL}/schooladministrators/{SCHOOLADMIN.cn}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_schooladmin_denied(self, user):
        r = client.get(f"{BASE_URL}/schooladministrators/{SCHOOLADMIN.cn}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]


class TestBindUsers:
    def test_get_globalbindusers_ga(self):
        r = client.get(f"{BASE_URL}/globalbindusers/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    @pytest.mark.parametrize("user", USERS[1:])
    def test_get_globalbindusers_denied(self, user):
        r = client.get(f"{BASE_URL}/globalbindusers/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_schoolbindusers_ga(self):
        r = client.get(f"{BASE_URL}/schoolbindusers/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_schoolbindusers_sa(self):
        r = client.get(f"{BASE_URL}/schoolbindusers/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_schoolbindusers_denied(self, user):
        r = client.get(f"{BASE_URL}/schoolbindusers/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]


class TestTeachers:
    def test_get_teachers_ga(self):
        r = client.get(f"{BASE_URL}/teachers/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_teachers_sa(self):
        r = client.get(f"{BASE_URL}/teachers/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_teachers_denied(self, user):
        r = client.get(f"{BASE_URL}/teachers/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_teacher_ga(self):
        r = client.get(f"{BASE_URL}/teachers/{TEACHER.cn}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == TEACHER.cn

    def test_get_teacher_sa(self):
        r = client.get(f"{BASE_URL}/teachers/{TEACHER.cn}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_teacher_denied(self, user):
        r = client.get(f"{BASE_URL}/teachers/{TEACHER.cn}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]
