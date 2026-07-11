import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]

_need_group = pytest.mark.skipif(GROUP == 'UNCONFIGURED', reason="GROUP not set in credentials.py")
_need_mgmt = pytest.mark.skipif(MGMT_GROUP == 'UNCONFIGURED', reason="MGMT_GROUP not set in credentials.py")


class TestGroups:
    def test_get_groups_ga(self):
        r = client.get(f"{BASE_URL}/groups/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_groups_sa(self):
        r = client.get(f"{BASE_URL}/groups/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_groups_denied(self, user):
        r = client.get(f"{BASE_URL}/groups/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_legacy_groups_ga(self):
        r = client.get(f"{BASE_URL}/groups/legacy", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_legacy_groups_sa(self):
        r = client.get(f"{BASE_URL}/groups/legacy", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_legacy_groups_denied(self, user):
        r = client.get(f"{BASE_URL}/groups/legacy", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_group
    def test_get_group_ga(self):
        r = client.get(f"{BASE_URL}/groups/{GROUP}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == GROUP

    @_need_group
    def test_get_group_sa(self):
        r = client.get(f"{BASE_URL}/groups/{GROUP}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_group_denied(self, user):
        r = client.get(f"{BASE_URL}/groups/{GROUP}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_post_group_denied(self, user):
        r = client.post(
            f"{BASE_URL}/groups/{GROUP}",
            headers={"X-API-KEY": user.jwt},
            json={}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_patch_group_denied(self, user):
        r = client.patch(
            f"{BASE_URL}/groups/{GROUP}",
            headers={"X-API-KEY": user.jwt},
            json={}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_delete_group_denied(self, user):
        r = client.delete(f"{BASE_URL}/groups/{GROUP}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_post_group_members_denied(self, user):
        r = client.post(
            f"{BASE_URL}/groups/{GROUP}/members",
            headers={"X-API-KEY": user.jwt},
            json={"users": []}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_delete_group_members_denied(self, user):
        r = client.request(
            "DELETE",
            f"{BASE_URL}/groups/{GROUP}/members",
            headers={"X-API-KEY": user.jwt},
            json={"users": []}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_post_migrate_group_denied(self, user):
        r = client.post(f"{BASE_URL}/groups/{GROUP}/migrate", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]


class TestManagementGroups:
    def test_get_managementgroups_ga(self):
        r = client.get(f"{BASE_URL}/managementgroups/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_managementgroups_sa(self):
        r = client.get(f"{BASE_URL}/managementgroups/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    def test_get_managementgroups_teacher(self):
        r = client.get(f"{BASE_URL}/managementgroups/", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_managementgroups_denied(self, user):
        r = client.get(f"{BASE_URL}/managementgroups/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_mgmt
    def test_get_managementgroup_ga(self):
        r = client.get(f"{BASE_URL}/managementgroups/{MGMT_GROUP}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == MGMT_GROUP

    @_need_mgmt
    def test_get_managementgroup_sa(self):
        r = client.get(f"{BASE_URL}/managementgroups/{MGMT_GROUP}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_managementgroup_denied(self, user):
        r = client.get(f"{BASE_URL}/managementgroups/{MGMT_GROUP}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[3:])
    def test_post_managementgroup_members_denied(self, user):
        r = client.post(
            f"{BASE_URL}/managementgroups/{MGMT_GROUP}/members",
            headers={"X-API-KEY": user.jwt},
            json={"users": []}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[3:])
    def test_delete_managementgroup_members_denied(self, user):
        r = client.request(
            "DELETE",
            f"{BASE_URL}/managementgroups/{MGMT_GROUP}/members",
            headers={"X-API-KEY": user.jwt},
            json={"users": []}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]
