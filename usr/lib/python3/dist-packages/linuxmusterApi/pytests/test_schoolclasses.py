import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]

_need_sc = pytest.mark.skipif(SCHOOLCLASS == 'UNCONFIGURED', reason="SCHOOLCLASS not set in credentials.py")


class TestSchoolClasses:
    def test_get_schoolclasses_ga(self):
        r = client.get(f"{BASE_URL}/schoolclasses/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_schoolclasses_sa(self):
        r = client.get(f"{BASE_URL}/schoolclasses/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    def test_get_schoolclasses_teacher(self):
        r = client.get(f"{BASE_URL}/schoolclasses/", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_schoolclasses_denied(self, user):
        r = client.get(f"{BASE_URL}/schoolclasses/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_sc
    def test_get_schoolclass_ga(self):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == SCHOOLCLASS

    @_need_sc
    def test_get_schoolclass_sa(self):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @_need_sc
    def test_get_schoolclass_teacher(self):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_schoolclass_denied(self, user):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_sc
    def test_get_schoolclass_all_members_ga(self):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}?all_members=true", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_schoolclass_all_members_denied(self, user):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}?all_members=true", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_sc
    def test_get_schoolclass_students_ga(self):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}/students", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_schoolclass_students_denied(self, user):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}/students", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_sc
    def test_get_schoolclass_parents_ga(self):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}/parents", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_schoolclass_parents_denied(self, user):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}/parents", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_sc
    def test_get_schoolclass_teachers_ga(self):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}/teachers", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_schoolclass_teachers_denied(self, user):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}/teachers", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_sc
    def test_get_schoolclass_first_passwords_ga(self):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}/first_passwords", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_schoolclass_first_passwords_denied(self, user):
        r = client.get(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}/first_passwords", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_patch_schoolclass_denied(self, user):
        r = client.patch(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}", headers={"X-API-KEY": user.jwt}, json={})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", [SCHOOLADMIN] + USERS[3:])
    def test_post_schoolclass_join_denied(self, user):
        r = client.post(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}/join", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", [SCHOOLADMIN] + USERS[3:])
    def test_post_schoolclass_quit_denied(self, user):
        r = client.post(f"{BASE_URL}/schoolclasses/{SCHOOLCLASS}/quit", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]
