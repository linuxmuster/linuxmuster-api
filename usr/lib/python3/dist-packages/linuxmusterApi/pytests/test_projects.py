import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]

_need_project = pytest.mark.skipif(PROJECT == 'UNCONFIGURED', reason="PROJECT not set in credentials.py")


class TestProjects:
    def test_get_projects_ga(self):
        r = client.get(f"{BASE_URL}/projects/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_projects_sa(self):
        r = client.get(f"{BASE_URL}/projects/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    def test_get_projects_teacher(self):
        r = client.get(f"{BASE_URL}/projects/", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_projects_denied(self, user):
        r = client.get(f"{BASE_URL}/projects/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_project
    def test_get_project_ga(self):
        r = client.get(f"{BASE_URL}/projects/{PROJECT}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == PROJECT

    @_need_project
    def test_get_project_sa(self):
        r = client.get(f"{BASE_URL}/projects/{PROJECT}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @_need_project
    def test_get_project_teacher(self):
        r = client.get(f"{BASE_URL}/projects/{PROJECT}", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_project_denied(self, user):
        r = client.get(f"{BASE_URL}/projects/{PROJECT}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_project
    def test_get_project_all_members_ga(self):
        r = client.get(f"{BASE_URL}/projects/{PROJECT}?all_members=true", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_project_all_members_denied(self, user):
        r = client.get(f"{BASE_URL}/projects/{PROJECT}?all_members=true", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[3:])
    def test_delete_project_denied(self, user):
        r = client.delete(f"{BASE_URL}/projects/{PROJECT}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[3:])
    def test_post_project_join_denied(self, user):
        r = client.post(f"{BASE_URL}/projects/{PROJECT}/join", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[3:])
    def test_post_project_quit_denied(self, user):
        r = client.post(f"{BASE_URL}/projects/{PROJECT}/quit", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]
