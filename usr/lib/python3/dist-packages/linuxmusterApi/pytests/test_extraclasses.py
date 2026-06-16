import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]

_need_ec = pytest.mark.skipif(EXTRACLASS == 'UNCONFIGURED', reason="EXTRACLASS not set in credentials.py")


class TestExtraClasses:
    def test_get_extraclasses_ga(self):
        r = client.get(f"{BASE_URL}/extraclasses/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_extraclasses_sa(self):
        r = client.get(f"{BASE_URL}/extraclasses/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    def test_get_extraclasses_teacher(self):
        r = client.get(f"{BASE_URL}/extraclasses/", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_extraclasses_denied(self, user):
        r = client.get(f"{BASE_URL}/extraclasses/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_ec
    def test_get_extraclass_ga(self):
        r = client.get(f"{BASE_URL}/extraclasses/{EXTRACLASS}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == EXTRACLASS

    @_need_ec
    def test_get_extraclass_sa(self):
        r = client.get(f"{BASE_URL}/extraclasses/{EXTRACLASS}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @_need_ec
    def test_get_extraclass_teacher(self):
        r = client.get(f"{BASE_URL}/extraclasses/{EXTRACLASS}", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_extraclass_denied(self, user):
        r = client.get(f"{BASE_URL}/extraclasses/{EXTRACLASS}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_ec
    def test_get_extraclass_all_members_ga(self):
        r = client.get(f"{BASE_URL}/extraclasses/{EXTRACLASS}?all_members=true", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_extraclass_all_members_denied(self, user):
        r = client.get(f"{BASE_URL}/extraclasses/{EXTRACLASS}?all_members=true", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]
