import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]

BAD_RULE_DEFAULT = {"schools": {SCHOOLADMIN.school: {"teacher": [{"type": "not-a-real-type"}]}}}


class TestPasswordConstraints:
    def test_get_ga(self):
        r = client.get(f"{BASE_URL}/passwordconstraints/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert "default" in data
        assert "schools" in data

    def test_get_sa(self):
        r = client.get(f"{BASE_URL}/passwordconstraints/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) == {"default", "school", "override"}
        assert data["school"] == SCHOOLADMIN.school

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_denied(self, user):
        r = client.get(f"{BASE_URL}/passwordconstraints/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_post_denied(self, user):
        r = client.post(f"{BASE_URL}/passwordconstraints/", headers={"X-API-KEY": user.jwt}, json={})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_post_invalid_rule_rejected(self):
        r = client.post(
            f"{BASE_URL}/passwordconstraints/",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
            json=BAD_RULE_DEFAULT)
        assert r.status_code == 400

    def test_post_sa_cannot_set_default(self):
        r = client.post(
            f"{BASE_URL}/passwordconstraints/",
            headers={"X-API-KEY": SCHOOLADMIN.jwt},
            json={"default": {"student": [{"type": "min_length", "value": 1}]}})
        assert r.status_code == 403

    def test_post_sa_cannot_set_other_school(self):
        r = client.post(
            f"{BASE_URL}/passwordconstraints/",
            headers={"X-API-KEY": SCHOOLADMIN.jwt},
            json={"schools": {"some-other-school": {"student": [{"type": "min_length", "value": 1}]}}})
        assert r.status_code == 403

    def test_post_ga_roundtrip(self):
        original = client.get(
            f"{BASE_URL}/passwordconstraints/", headers={"X-API-KEY": GLOBALADMIN.jwt}).json()
        try:
            r = client.post(
                f"{BASE_URL}/passwordconstraints/",
                headers={"X-API-KEY": GLOBALADMIN.jwt},
                json=original)
            assert r.status_code == 200
        finally:
            client.post(
                f"{BASE_URL}/passwordconstraints/",
                headers={"X-API-KEY": GLOBALADMIN.jwt},
                json=original)

    def test_post_sa_roundtrip_own_school(self):
        before = client.get(
            f"{BASE_URL}/passwordconstraints/", headers={"X-API-KEY": SCHOOLADMIN.jwt}).json()
        payload = {"schools": {SCHOOLADMIN.school: before["override"]}}
        try:
            r = client.post(
                f"{BASE_URL}/passwordconstraints/",
                headers={"X-API-KEY": SCHOOLADMIN.jwt},
                json=payload)
            assert r.status_code == 200
        finally:
            client.post(
                f"{BASE_URL}/passwordconstraints/",
                headers={"X-API-KEY": SCHOOLADMIN.jwt},
                json=payload)
