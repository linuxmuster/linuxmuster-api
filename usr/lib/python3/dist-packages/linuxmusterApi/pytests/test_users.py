import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]


class TestUsers:
    def test_get_users_ga(self):
        r = client.get(f"{BASE_URL}/users/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) > 0

    @pytest.mark.parametrize("user", USERS[1:])
    def test_get_users_denied(self, user):
        r = client.get(f"{BASE_URL}/users/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_user_ga_accesses_teacher(self):
        r = client.get(f"{BASE_URL}/users/{TEACHER.cn}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == TEACHER.cn

    def test_get_user_teacher_accesses_own(self):
        r = client.get(f"{BASE_URL}/users/{TEACHER.cn}", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == TEACHER.cn

    def test_get_user_student_accesses_own(self):
        r = client.get(f"{BASE_URL}/users/{STUDENT.cn}", headers={"X-API-KEY": STUDENT.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == STUDENT.cn
