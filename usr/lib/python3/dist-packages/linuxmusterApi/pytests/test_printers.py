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

    @_need_printer
    def test_patch_printer_leaves_unsent_attributes_alone(self):
        """
        A partial patch must not rewrite what the caller never sent. The
        schema used to default join to True and hide to False, so a patch
        adding a member also unhid the printer and made it joinable.
        """

        url = f"{BASE_URL}/printers/{PRINTER}"
        headers = {"X-API-KEY": GLOBALADMIN.jwt}
        before = client.get(url, headers=headers).json()
        restore = {
            "join": before["sophomorixJoinable"],
            "hide": before["sophomorixHidden"],
            "school": before["sophomorixSchoolname"],
            "description": before["description"],
        }

        try:
            # Put the printer in a state that differs from the old defaults
            client.patch(url, headers=headers, json=dict(restore, join=False, hide=True))
            staged = client.get(url, headers=headers).json()
            assert staged["sophomorixJoinable"] is False
            assert staged["sophomorixHidden"] is True

            # A patch that only carries a description must change only that
            r = client.patch(url, headers=headers, json={"description": "partial patch"})
            assert r.status_code == 204

            after = client.get(url, headers=headers).json()
            assert after["description"] == "partial patch"
            assert after["sophomorixJoinable"] is False
            assert after["sophomorixHidden"] is True
            assert after["sophomorixSchoolname"] == restore["school"]
        finally:
            client.patch(url, headers=headers, json=restore)

    @_need_printer
    def test_patch_printer_still_applies_what_is_sent(self):
        """The guard must not swallow an explicit false."""

        url = f"{BASE_URL}/printers/{PRINTER}"
        headers = {"X-API-KEY": GLOBALADMIN.jwt}
        before = client.get(url, headers=headers).json()
        restore = {
            "join": before["sophomorixJoinable"],
            "hide": before["sophomorixHidden"],
            "school": before["sophomorixSchoolname"],
            "description": before["description"],
        }

        try:
            client.patch(url, headers=headers, json={"join": False})
            assert client.get(url, headers=headers).json()["sophomorixJoinable"] is False

            client.patch(url, headers=headers, json={"join": True})
            assert client.get(url, headers=headers).json()["sophomorixJoinable"] is True
        finally:
            client.patch(url, headers=headers, json=restore)

