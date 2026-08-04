import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app
from routers_v1 import users as users_router
import linuxmusterTools.passwords as lmn_passwords
from linuxmusterTools.passwords.policy import CharClass, MinLengthRule, RequireClassesRule, PasswordPolicy

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]

_FIXED_POLICY = PasswordPolicy(rules=(
    MinLengthRule(8),
    RequireClassesRule(classes=(CharClass.UPPER, CharClass.DIGIT, CharClass.SPECIAL)),
))


class _FixedPasswordPolicyProvider:
    """
    Deterministic stand-in for PasswordPolicyProvider. Tests must never
    depend on this server's actual /etc/linuxmuster/tools/password_constraints.yml
    or its live Samba AD domain policy — both are simulated here instead.
    """

    def get_policy(self, role, school="default-school"):
        return _FIXED_POLICY

    def validate(self, password, role, school="default-school", *, username=None):
        return _FIXED_POLICY.validate(password, username=username)


@pytest.fixture(autouse=True, scope="module")
def _fixed_password_policy():
    # Two separate injection points: the module-level singleton used by
    # set-first-password/set-current-password, and the class itself, used by
    # LMNUser.set_random_first_password() (linuxmusterTools), which
    # instantiates its own PasswordPolicyProvider() internally.
    mp = pytest.MonkeyPatch()
    mp.setattr(users_router, "password_policy_provider", _FixedPasswordPolicyProvider())
    mp.setattr(lmn_passwords, "PasswordPolicyProvider", _FixedPasswordPolicyProvider)
    yield
    mp.undo()


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
    Password constraint enforcement on set-first-password/set-current-password,
    against the fixed policy simulated by _fixed_password_policy (see above).
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

    def test_set_first_password_omitted_resets_to_existing_first_password(self):
        # Note: this does not attempt to prove the current password actually
        # drifted away from the first password beforehand and back — Samba
        # AD keeps a just-changed-from password valid for a grace period
        # (~60 min), which would make such a check flaky. It only checks
        # that omitting `password` is accepted and leaves the account in a
        # state where the current password matches the stored first one.
        r = client.post(
            f"{BASE_URL}/users/{STUDENT.cn}/set-first-password",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
            json={"password": self.STRONG_PASSWORD, "set_current": True},
        )
        assert r.status_code == 200

        r = client.post(
            f"{BASE_URL}/users/{STUDENT.cn}/set-first-password",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
            json={},
        )
        assert r.status_code == 200

        r = client.get(
            f"{BASE_URL}/users/{STUDENT.cn}",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
            params={"check_first_pw": True},
        )
        assert r.json()["FirstPasswordSet"] is True


class TestUserRandomFirstPassword:
    """
    set-random-first-password: linuxmuster-api generates the password itself
    (satisfying the current policy) and returns it.
    """

    @pytest.fixture(autouse=True)
    def _restore_known_password(self):
        # The generated password is unknown once the test ends; put the
        # account back on a known, policy-compliant value (same one
        # TestUserPasswords already leaves it on) instead of an unrecoverable
        # random one, in case another test run depends on it.
        yield
        client.post(
            f"{BASE_URL}/users/{STUDENT.cn}/set-first-password",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
            json={"password": TestUserPasswords.STRONG_PASSWORD, "set_current": True},
        )

    def test_set_random_first_password_returns_and_sets_a_password(self):
        r = client.post(
            f"{BASE_URL}/users/{STUDENT.cn}/set-random-first-password",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
        )
        assert r.status_code == 200

        password = r.json()["password"]
        assert isinstance(password, str) and len(password) > 0

        r = client.get(
            f"{BASE_URL}/users/{STUDENT.cn}",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
            params={"check_first_pw": True},
        )
        assert r.json()["FirstPasswordSet"] is True
