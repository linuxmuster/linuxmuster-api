import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]

_need_printer = pytest.mark.skipif(PRINTER == 'UNCONFIGURED', reason="PRINTER not set in credentials.py")


class TestPrinters:
    def test_get_printers_ga(self):
        r = client.get(f"{BASE_URL}/printers/", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_printers_sa(self):
        r = client.get(f"{BASE_URL}/printers/", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    def test_get_printers_teacher(self):
        r = client.get(f"{BASE_URL}/printers/", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_printers_denied(self, user):
        r = client.get(f"{BASE_URL}/printers/", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @_need_printer
    def test_get_printer_ga(self):
        r = client.get(f"{BASE_URL}/printers/{PRINTER}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert data["cn"] == PRINTER

    @_need_printer
    def test_get_printer_sa(self):
        r = client.get(f"{BASE_URL}/printers/{PRINTER}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @_need_printer
    def test_get_printer_teacher(self):
        r = client.get(f"{BASE_URL}/printers/{PRINTER}", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_printer_denied(self, user):
        r = client.get(f"{BASE_URL}/printers/{PRINTER}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_patch_printer_denied(self, user):
        r = client.patch(f"{BASE_URL}/printers/{PRINTER}", headers={"X-API-KEY": user.jwt}, json={})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", [SCHOOLADMIN] + USERS[3:])
    def test_post_printer_join_denied(self, user):
        r = client.post(f"{BASE_URL}/printers/{PRINTER}/join", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", [SCHOOLADMIN] + USERS[3:])
    def test_post_printer_quit_denied(self, user):
        r = client.post(f"{BASE_URL}/printers/{PRINTER}/quit", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]
