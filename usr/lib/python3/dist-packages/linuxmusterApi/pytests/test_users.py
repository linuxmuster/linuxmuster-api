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


class TestUserPasswords:
    """
    Password constraint enforcement on set-first-password/set-current-password.
    Uses passwords deliberately far from any reasonable policy on either side
    (too weak to pass any config, long/varied enough to pass any config) so
    these tests don't depend on the server's own password_constraints.yml.
    """

    WEAK_PASSWORD = "weak"
    STRONG_PASSWORD = "Str0ngP@ssw0rd!"

    def test_set_first_password_weak_rejected(self):
        r = client.post(
            f"{BASE_URL}/users/{STUDENT.cn}/set-first-password",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
            json={"password": self.WEAK_PASSWORD, "set_current": False},
        )
        assert r.status_code == 400
        assert "does not meet requirements" in r.json()["detail"]

    def test_set_first_password_strong_accepted(self):
        r = client.post(
            f"{BASE_URL}/users/{STUDENT.cn}/set-first-password",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
            json={"password": self.STRONG_PASSWORD, "set_current": False},
        )
        assert r.status_code == 200

    def test_set_current_password_weak_rejected(self):
        r = client.post(
            f"{BASE_URL}/users/{STUDENT.cn}/set-current-password",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
            json={"password": self.WEAK_PASSWORD, "set_first": False},
        )
        assert r.status_code == 400
        assert "does not meet requirements" in r.json()["detail"]

    def test_set_current_password_strong_accepted(self):
        r = client.post(
            f"{BASE_URL}/users/{STUDENT.cn}/set-current-password",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
            json={"password": self.STRONG_PASSWORD, "set_first": False},
        )
        assert r.status_code == 200
