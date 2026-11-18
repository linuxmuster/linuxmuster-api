import sys
import time
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

    @pytest.mark.parametrize("member", [GLOBALADMIN, SCHOOLADMIN])
    def test_post_session_teacher_higher_member_denied(self, member):
        r = client.post(
            f"{BASE_URL}/sessions/{TEACHER.cn}/pytest-denied",
            json={'users': [STUDENT.cn, member.cn]},
            headers={"X-API-KEY": TEACHER.jwt}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("method", ["POST", "DELETE"])
    def test_members_teacher_other_owner_denied(self, method):
        r = client.request(
            method,
            f"{BASE_URL}/sessions/{SCHOOLADMIN.cn}/nonexistent-session-id/members",
            json={'users': [STUDENT.cn]},
            headers={"X-API-KEY": TEACHER.jwt}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_session_teacher_first_password_students_only(self):
        # The sid is a timestamp to the second: avoid sharing it with a session created just before
        time.sleep(1)
        # Only a global-administrator can put a school-administrator in a teacher's session
        r = client.post(
            f"{BASE_URL}/sessions/{TEACHER.cn}/pytest-mask",
            json={'users': [STUDENT.cn, SCHOOLADMIN.cn]},
            headers={"X-API-KEY": GLOBALADMIN.jwt}
        )
        assert r.status_code == 200

        r = client.get(f"{BASE_URL}/sessions/{TEACHER.cn}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        sid = [s['sid'] for s in r.json() if s['name'] == 'pytest-mask'][-1]

        try:
            for url in (f"{BASE_URL}/sessions/{TEACHER.cn}/{sid}", f"{BASE_URL}/sessions/{TEACHER.cn}?members_details=true"):
                r = client.get(url, headers={"X-API-KEY": TEACHER.jwt})
                assert r.status_code == 200
                data = r.json()
                members = data['members'] if isinstance(data, dict) else [m for s in data if s['sid'] == sid for m in s['members']]
                roles = {m["sAMAccountName"]: m for m in members}
                assert 'sophomorixFirstPassword' not in roles[SCHOOLADMIN.cn]
                assert 'sophomorixFirstPassword' in roles[STUDENT.cn]
        finally:
            client.delete(f"{BASE_URL}/sessions/{TEACHER.cn}/{sid}", headers={"X-API-KEY": GLOBALADMIN.jwt})
