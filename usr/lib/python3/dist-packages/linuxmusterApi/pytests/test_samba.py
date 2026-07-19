import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]


class TestSambaPasswordPolicy:
    def test_get_ga(self):
        r = client.get(f"{BASE_URL}/samba/passwordpolicy", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) == {"min_pwd_length", "complexity", "min_pwd_age", "max_pwd_age"}

    def test_get_sa(self):
        r = client.get(f"{BASE_URL}/samba/passwordpolicy", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_denied(self, user):
        r = client.get(f"{BASE_URL}/samba/passwordpolicy", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", [SCHOOLADMIN] + USERS[2:])
    def test_post_denied(self, user):
        r = client.post(
            f"{BASE_URL}/samba/passwordpolicy",
            headers={"X-API-KEY": user.jwt},
            json={"min_pwd_length": 8})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_post_empty_body_rejected(self):
        r = client.post(
            f"{BASE_URL}/samba/passwordpolicy",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
            json={})
        assert r.status_code == 400

    def test_post_ga_roundtrip(self):
        before = client.get(
            f"{BASE_URL}/samba/passwordpolicy", headers={"X-API-KEY": GLOBALADMIN.jwt}).json()
        try:
            r = client.post(
                f"{BASE_URL}/samba/passwordpolicy",
                headers={"X-API-KEY": GLOBALADMIN.jwt},
                json=before)
            assert r.status_code == 200
            assert r.json() == before
        finally:
            client.post(
                f"{BASE_URL}/samba/passwordpolicy",
                headers={"X-API-KEY": GLOBALADMIN.jwt},
                json=before)
