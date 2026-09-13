import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]


class TestRoles:
    def test_get_roles_ga(self):
        r = client.get(f"{BASE_URL}/roles/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_roles_sa(self):
        r = client.get(f"{BASE_URL}/roles/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_roles_denied(self, user):
        r = client.get(f"{BASE_URL}/roles/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_roles_teachers_ga(self):
        r = client.get(f"{BASE_URL}/roles/teachers", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_roles_teachers_sa(self):
        r = client.get(f"{BASE_URL}/roles/teachers", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_roles_teachers_denied(self, user):
        r = client.get(f"{BASE_URL}/roles/teachers", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

class TestRolesSchoolScoping:
    """
    A school-administrator used to reach every school by naming it, and the
    whole directory by naming none (schooladm.txt, 2026-09-01).
    """

    def test_another_school_is_403(self):
        r = client.get(
            f"{BASE_URL}/roles/teacher",
            params={"school": "other-school"},
            headers={"X-API-KEY": SCHOOLADMIN.jwt},
        )
        assert r.status_code == 403

    def test_an_empty_school_stays_in_the_caller_school(self):
        r = client.get(
            f"{BASE_URL}/roles/teacher",
            params={"school": ""},
            headers={"X-API-KEY": SCHOOLADMIN.jwt},
        )
        assert r.status_code == 200
        assert {u['sophomorixSchoolname'] for u in r.json()} <= {SCHOOLADMIN.school}

    def test_no_school_at_all_stays_in_the_caller_school(self):
        r = client.get(f"{BASE_URL}/roles/teacher", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200
        assert {u['sophomorixSchoolname'] for u in r.json()} <= {SCHOOLADMIN.school}

    def test_a_global_role_is_denied_to_a_school_admin(self):
        # Global roles are read unfiltered, since they live outside of any
        # school: that read belongs to global-administrators only.
        r = client.get(
            f"{BASE_URL}/roles/globaladministrator",
            headers={"X-API-KEY": SCHOOLADMIN.jwt},
        )
        assert r.status_code == 403

    def test_a_global_role_is_readable_by_a_global_admin(self):
        r = client.get(
            f"{BASE_URL}/roles/globaladministrator",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_a_global_admin_naming_no_school_still_reads_default_school(self):
        r = client.get(f"{BASE_URL}/roles/teacher", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        assert {u['sophomorixSchoolname'] for u in r.json()} <= {'default-school'}


class TestServer:
    def test_get_lmnversion_ga(self):
        r = client.get(f"{BASE_URL}/server/lmnversion", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)
        assert len(data) > 0

    def test_get_lmnversion_sa(self):
        r = client.get(f"{BASE_URL}/server/lmnversion", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_lmnversion_denied(self, user):
        r = client.get(f"{BASE_URL}/server/lmnversion", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]
