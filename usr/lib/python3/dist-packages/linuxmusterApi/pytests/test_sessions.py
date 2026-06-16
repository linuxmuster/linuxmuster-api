import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]


class TestSessions:
    def test_get_sessions_ga_accesses_teacher(self):
        r = client.get(f"{BASE_URL}/sessions/{TEACHER.cn}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_sessions_teacher_accesses_own(self):
        r = client.get(f"{BASE_URL}/sessions/{TEACHER.cn}", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_sessions_student_accesses_own(self):
        r = client.get(f"{BASE_URL}/sessions/{STUDENT.cn}", headers={"X-API-KEY": STUDENT.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_post_session_teacher_creates_own(self):
        r = client.post(
            f"{BASE_URL}/sessions/{TEACHER.cn}/test-session",
            headers={"X-API-KEY": TEACHER.jwt}
        )
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_delete_session_denied(self, user):
        r = client.delete(
            f"{BASE_URL}/sessions/{TEACHER.cn}/nonexistent-session-id",
            headers={"X-API-KEY": user.jwt}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]
