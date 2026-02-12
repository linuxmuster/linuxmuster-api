import sys
import json
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app


client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]

class TestSchools:
    def test_get_schools_ga(self):
        user = GLOBALADMIN

        r = client.get(f"{BASE_URL}/schools", headers={"X-API-KEY": user.jwt})
        schools = json.loads(r.content.decode("utf-8"))

        assert r.status_code == 200
        assert 'default-school' in schools[0]["ou"]

    @pytest.mark.parametrize("user", USERS[1:])
    def test_get_schools_others_roles(self, user):
        r = client.get(f"{BASE_URL}/schools", headers={"X-API-KEY": user.jwt})
        detail = json.loads(r.content.decode("utf-8"))["detail"]

        assert r.status_code == 401
        assert 'Permission denied' in detail

    def test_get_default_school_ga(self):
        user = GLOBALADMIN

        r = client.get(f"{BASE_URL}/schools/default-school", headers={"X-API-KEY": user.jwt})
        school = json.loads(r.content.decode("utf-8"))

        assert r.status_code == 200
        assert school['ou'] == 'default-school'
        assert "schoolclasses" in school
        assert "projects" in school
        assert "staff" in school

    @pytest.mark.parametrize("user", USERS[1:])
    def test_get_default_school_others_roles(self, user):
        r = client.get(f"{BASE_URL}/schools/default-school", headers={"X-API-KEY": user.jwt})
        detail = json.loads(r.content.decode("utf-8"))["detail"]

        assert r.status_code == 401
        assert 'Permission denied' in detail


    def test_get_wrong_school_ga(self):
        user = GLOBALADMIN
        r = client.get(f"{BASE_URL}/schools/defaut-school", headers={"X-API-KEY": user.jwt})

        assert r.status_code == 404

    @pytest.mark.parametrize("user", USERS[1:])
    def test_get_wrong_school_others_roles(self, user):
        r = client.get(f"{BASE_URL}/schools/default-school", headers={"X-API-KEY": user.jwt})
        detail = json.loads(r.content.decode("utf-8"))["detail"]

        assert r.status_code == 401
        assert 'Permission denied' in detail
