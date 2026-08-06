import os
import sys

import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app
import routers_v1.listmanagement as listmanagement


client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]


@pytest.fixture(autouse=True)
def fake_process_user(monkeypatch):
    """
    Both endpoints under test schedule utils.sophomorix.process_user as a
    BackgroundTask, and TestClient runs background tasks synchronously
    before the response comes back — replace it so no real sophomorix
    subprocess/webhook ever runs from this test file.

    tempfile.mkstemp() in the endpoint itself still really creates the empty
    {pid}.sophomorix.log placeholder on disk (that part isn't mocked), so
    clean those up afterward instead of littering /tmp/lmnapi.
    """

    calls = []
    monkeypatch.setattr(listmanagement, 'process_user', lambda *a, **kw: calls.append((a, kw)))
    yield calls
    for args, kwargs in calls:
        pid = args[1]
        logpath = f"/tmp/lmnapi/{pid}.sophomorix.log"
        if os.path.isfile(logpath):
            os.remove(logpath)


class TestSophomorixCheck:

    @pytest.mark.parametrize("user", USERS[2:])
    def test_denied(self, user):
        r = client.get(f"{BASE_URL}/listmanagement/sophomorix-check", headers={"X-API-Key": user.jwt})
        assert r.status_code == 401

    def test_ga_returns_pid_and_schedules_job(self, fake_process_user):
        r = client.get(f"{BASE_URL}/listmanagement/sophomorix-check", headers={"X-API-Key": GLOBALADMIN.jwt})

        assert r.status_code == 200
        pid = r.json()
        assert isinstance(pid, str) and pid

        assert len(fake_process_user) == 1
        args, kwargs = fake_process_user[0]
        assert kwargs['command'] == 'sophomorix-check'
        assert kwargs['school'] == GLOBALADMIN.school
        assert kwargs['caller'] == GLOBALADMIN.cn
        assert args[1] == pid  # (script, pid, ...)
        # -jj's JSON payload is on stderr: both streams must reach the log.
        assert '2>&1' in args[0]

    def test_sa_returns_pid(self, fake_process_user):
        r = client.get(f"{BASE_URL}/listmanagement/sophomorix-check", headers={"X-API-Key": SCHOOLADMIN.jwt})

        assert r.status_code == 200
        assert len(fake_process_user) == 1


class TestSophomorixApply:

    @pytest.mark.parametrize("user", USERS[2:])
    def test_denied(self, user):
        r = client.get(
            f"{BASE_URL}/listmanagement/sophomorix-apply",
            params={"school": "default-school", "add": True},
            headers={"X-API-Key": user.jwt},
        )
        assert r.status_code == 401

    def test_invalid_school_is_404(self):
        r = client.get(
            f"{BASE_URL}/listmanagement/sophomorix-apply",
            params={"school": "not-a-real-school", "add": True},
            headers={"X-API-Key": GLOBALADMIN.jwt},
        )
        assert r.status_code == 404

    def test_school_admin_other_school_is_403(self, monkeypatch):
        # This test LDAP only has one real school (default-school, which is
        # also SCHOOLADMIN's own), so the 403 branch can't be reached with a
        # genuinely valid second school — fake the school list instead.
        monkeypatch.setattr(listmanagement.lr, 'getval', lambda *a, **k: ['default-school', 'other-school'])

        r = client.get(
            f"{BASE_URL}/listmanagement/sophomorix-apply",
            params={"school": "other-school", "add": True},
            headers={"X-API-Key": SCHOOLADMIN.jwt},
        )
        assert r.status_code == 403

    def test_returns_pid_and_schedules_selected_commands_only(self, fake_process_user):
        r = client.get(
            f"{BASE_URL}/listmanagement/sophomorix-apply",
            params={"school": "default-school", "add": True, "kill": True},
            headers={"X-API-Key": GLOBALADMIN.jwt},
        )

        assert r.status_code == 200
        pid = r.json()
        assert isinstance(pid, str) and pid

        assert len(fake_process_user) == 1
        args, kwargs = fake_process_user[0]
        assert kwargs['command'] == 'sophomorix-add+sophomorix-kill'
        assert kwargs['school'] == 'default-school'
        assert kwargs['caller'] == GLOBALADMIN.cn
        script = args[0]
        assert 'sophomorix-add' in script
        assert 'sophomorix-kill' in script
        assert 'sophomorix-update' not in script


class TestSophomorixApplyStatus:

    @pytest.mark.parametrize("user", USERS[2:])
    def test_denied(self, user):
        r = client.get(f"{BASE_URL}/listmanagement/sophomorix-apply/status/ghost", headers={"X-API-Key": user.jwt})
        assert r.status_code == 401

    def test_unknown_pid_is_404(self):
        r = client.get(f"{BASE_URL}/listmanagement/sophomorix-apply/status/does-not-exist", headers={"X-API-Key": GLOBALADMIN.jwt})
        assert r.status_code == 404

    def test_reads_back_log_and_status_regardless_of_which_endpoint_created_them(self):
        # Same files whether the job originated from sophomorix-check or
        # sophomorix-apply — the status endpoint doesn't care which.
        pid = 'pytest.status.check'
        logpath = f"/tmp/lmnapi/{pid}.sophomorix.log"
        statuspath = f"/tmp/lmnapi/{pid}.sophomorix.status"
        os.makedirs('/tmp/lmnapi', exist_ok=True)
        with open(logpath, 'w') as f:
            f.write('line1\nline2\n')
        with open(statuspath, 'w') as f:
            f.write('Process pytest.status.check was started ... and was completed at ...')

        try:
            r = client.get(f"{BASE_URL}/listmanagement/sophomorix-apply/status/{pid}", headers={"X-API-Key": GLOBALADMIN.jwt})
            assert r.status_code == 200
            data = r.json()
            assert data['log'] == ['line1\n', 'line2\n']
            assert 'completed' in data['status']
        finally:
            os.remove(logpath)
            os.remove(statuspath)
