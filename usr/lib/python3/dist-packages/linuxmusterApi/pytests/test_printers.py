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

    @_need_printer
    def test_patch_printer_can_remove_the_last_member(self):
        """
        Clearing the member list is a valid state. setattr() refuses an empty
        value, so the endpoint has to go through delattr() instead of raising
        a ValueError and answering 500.
        """

        url = f"{BASE_URL}/printers/{PRINTER}"
        headers = {"X-API-KEY": GLOBALADMIN.jwt}
        members = [
            dn.split(",")[0].removeprefix("CN=")
            for dn in client.get(url, headers=headers).json()["member"]
        ]
        if not members:
            pytest.skip(f"Printer {PRINTER} has no member to remove")

        try:
            r = client.patch(url, headers=headers, json={"removemembers": members})
            assert r.status_code == 204
            assert client.get(url, headers=headers).json()["member"] == []
        finally:
            client.patch(url, headers=headers, json={"addmembers": members})

        assert len(client.get(url, headers=headers).json()["member"]) == len(members)

    @_need_printer
    @pytest.mark.parametrize("field,kind", [
        ("addmembers", "User"),
        ("removemembers", "User"),
        ("addmembergroups", "Group"),
        ("removemembergroups", "Group"),
    ])
    def test_patch_printer_404s_on_an_unknown_name(self, field, kind):
        """
        getval() answers None for a name that does not exist. That None used
        to reach the LDAP modify as a DN, answering 500 with an
        INVALID_DN_SYNTAX the caller cannot act on.
        """

        url = f"{BASE_URL}/printers/{PRINTER}"
        headers = {"X-API-KEY": GLOBALADMIN.jwt}
        before = client.get(url, headers=headers).json()["member"]

        r = client.patch(url, headers=headers, json={field: ["does-not-exist-xyz"]})
        assert r.status_code == 404
        assert r.json()["detail"] == f"{kind} does-not-exist-xyz not found"

        # The whole patch is refused: nothing was written
        assert client.get(url, headers=headers).json()["member"] == before

    @_need_printer
    def test_patch_printer_400s_on_an_exam_account(self):
        """
        The /users/ route only matches the six regular sophomorix roles, so an
        exam account resolves to None like an unknown name would. Answering
        "User <cn> not found" for an account that does exist — and that the
        webui search does offer — sends the caller hunting for a typo.
        """

        from linuxmusterTools.ldapconnector import LMNLdapReader as lr

        examusers = lr.get('/users/exam', attributes=['cn'])
        if not examusers:
            pytest.skip("No exam account in this LDAP")

        examuser = examusers[0]['cn']
        url = f"{BASE_URL}/printers/{PRINTER}"
        headers = {"X-API-KEY": GLOBALADMIN.jwt}
        before = client.get(url, headers=headers).json()["member"]

        r = client.patch(url, headers=headers, json={"addmembers": [examuser]})
        assert r.status_code == 400
        assert r.json()["detail"] == f"User {examuser} is an exam account and cannot be used here"

        # The whole patch is refused: nothing was written
        assert client.get(url, headers=headers).json()["member"] == before
