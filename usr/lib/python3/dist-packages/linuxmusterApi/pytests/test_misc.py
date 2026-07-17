import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app
from routers_v1 import linbo as linbo_router

client = TestClient(app)
client_no_raise = TestClient(app, raise_server_exceptions=False)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]


def _raise_error(error):
    def fail(*_args, **_kwargs):
        raise error

    return fail


class TestQuery:
    def test_query_ga(self):
        r = client.get(f"{BASE_URL}/query/{SCHOOL}/{TEACHER.cn}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_query_sa(self):
        r = client.get(f"{BASE_URL}/query/{SCHOOL}/{TEACHER.cn}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    def test_query_teacher(self):
        r = client.get(f"{BASE_URL}/query/{SCHOOL}/{TEACHER.cn}", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_query_denied(self, user):
        r = client.get(f"{BASE_URL}/query/{SCHOOL}/{TEACHER.cn}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]


class TestSamba:
    def test_smbstatus_ga(self):
        r = client_no_raise.get(f"{BASE_URL}/samba/smbstatus", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code != 401

    def test_smbstatus_sa(self):
        r = client_no_raise.get(f"{BASE_URL}/samba/smbstatus", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code != 401

    def test_smbstatus_teacher(self):
        r = client.get(f"{BASE_URL}/samba/smbstatus", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_smbstatus_denied(self, user):
        r = client.get(f"{BASE_URL}/samba/smbstatus", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]


class TestExam:
    @pytest.mark.parametrize("user", USERS[3:])
    def test_post_exammode_start_denied(self, user):
        r = client.post(f"{BASE_URL}/exammode/start", headers={"X-API-KEY": user.jwt}, json={"users": []})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[3:])
    def test_post_exammode_stop_denied(self, user):
        r = client.post(f"{BASE_URL}/exammode/stop", headers={"X-API-KEY": user.jwt}, json={"users": []})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_exammode_users_ga(self):
        r = client.get(f"{BASE_URL}/exammode/users", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_exammode_users_sa(self):
        r = client.get(f"{BASE_URL}/exammode/users", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    def test_get_exammode_users_teacher(self):
        r = client.get(f"{BASE_URL}/exammode/users", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_exammode_users_denied(self, user):
        r = client.get(f"{BASE_URL}/exammode/users", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_exammode_user_ga(self):
        r = client.get(f"{BASE_URL}/exammode/users/{TEACHER.cn}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200

    def test_get_exammode_user_sa(self):
        r = client.get(f"{BASE_URL}/exammode/users/{TEACHER.cn}", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    def test_get_exammode_user_teacher(self):
        r = client.get(f"{BASE_URL}/exammode/users/{TEACHER.cn}", headers={"X-API-KEY": TEACHER.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[3:])
    def test_get_exammode_user_denied(self, user):
        r = client.get(f"{BASE_URL}/exammode/users/{TEACHER.cn}", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]


class TestListManagement:
    def test_get_listmanagement_ga(self):
        r = client.get(f"{BASE_URL}/listmanagement/{SCHOOL}/students", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200

    def test_get_listmanagement_sa(self):
        r = client.get(f"{BASE_URL}/listmanagement/{SCHOOL}/students", headers={"X-API-KEY": SCHOOLADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[2:])
    def test_get_listmanagement_denied(self, user):
        r = client.get(f"{BASE_URL}/listmanagement/{SCHOOL}/students", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_post_listmanagement_denied(self, user):
        r = client.post(
            f"{BASE_URL}/listmanagement/{SCHOOL}/students",
            headers={"X-API-KEY": user.jwt},
            json=[]
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]


class TestLinbo:
    def test_get_linbo_health_ga(self):
        r = client.get(f"{BASE_URL}/linbo/health", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[1:])
    def test_get_linbo_health_denied(self, user):
        r = client.get(f"{BASE_URL}/linbo/health", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    def test_get_linbo_server_info_ga(self):
        r = client.get(f"{BASE_URL}/linbo/server-info", headers={"X-API-KEY": GLOBALADMIN.jwt})
        assert r.status_code == 200

    @pytest.mark.parametrize("user", USERS[1:])
    def test_get_linbo_server_info_denied(self, user):
        r = client.get(f"{BASE_URL}/linbo/server-info", headers={"X-API-KEY": user.jwt})
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[1:])
    def test_post_linbo_startconf_denied(self, user):
        r = client.post(
            f"{BASE_URL}/linbo/startconfs/pytest-startconf",
            headers={"X-API-KEY": user.jwt},
            json={"content": "[LINBO]\nServer = 10.0.0.1\n"},
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[1:])
    def test_delete_linbo_startconf_denied(self, user):
        r = client.delete(
            f"{BASE_URL}/linbo/startconfs/pytest-startconf",
            headers={"X-API-KEY": user.jwt},
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("endpoint", ["profiles", "images", "inventory"])
    def test_get_linbo_drivers_ga(self, endpoint):
        r = client.get(
            f"{BASE_URL}/linbo/drivers/{endpoint}",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @pytest.mark.parametrize(
        "error",
        [
            linbo_router.DriverHookOwnershipError("existing hook is not managed"),
            linbo_router.DriverHookTransactionError(
                "image upload transaction failed",
                cause=linbo_router.DriverHookOwnershipError(
                    "existing hook is not managed"
                ),
            ),
        ],
    )
    def test_finalize_upload_maps_hook_ownership_to_conflict(
        self,
        monkeypatch,
        error,
    ):
        monkeypatch.setattr(
            linbo_router,
            "finalize_upload",
            _raise_error(error),
        )
        r = client.post(
            f"{BASE_URL}/linbo/images/upload/win11/complete",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
        )

        assert r.status_code == 409
        assert r.json()["detail"] == "existing hook is not managed"

    @pytest.mark.parametrize(
        "target,endpoint,protected_path",
        [
            (
                "finalize_upload",
                "images/upload/win11/complete",
                "/srv/linbo/images/win11/private-target",
            ),
            (
                "reconcile_driver_hooks",
                "drivers/hooks/reconcile",
                "/srv/linbo/drivers/.driver-profiles.lock",
            ),
        ],
    )
    def test_linbo_driver_storage_errors_hide_server_paths(
        self,
        monkeypatch,
        target,
        endpoint,
        protected_path,
    ):
        fail = _raise_error(
            linbo_router.StorageSecurityError(
                f"unsafe path: {protected_path}"
            )
        )
        if target == "finalize_upload":
            monkeypatch.setattr(linbo_router, target, fail)
        else:
            monkeypatch.setattr(
                linbo_router.LinboDriverManager,
                target,
                fail,
            )
        r = client.post(
            f"{BASE_URL}/linbo/{endpoint}",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
        )

        assert r.status_code == 500
        assert r.json()["detail"] == "LINBO driver storage safety check failed"
        assert protected_path not in r.json()["detail"]

    def test_reconcile_driver_hooks_passes_through_tools_result(self, monkeypatch):
        expected = {
            "regenerated": ["win11"],
            "failed": [{"image": "broken", "message": "fixture"}],
        }
        monkeypatch.setattr(
            linbo_router.LinboDriverManager,
            "reconcile_driver_hooks",
            lambda _manager: expected,
        )

        r = client.post(
            f"{BASE_URL}/linbo/drivers/hooks/reconcile",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
        )

        assert r.status_code == 200
        assert r.json() == expected

    @pytest.mark.parametrize(
        "error,status_code,detail",
        [
            (
                linbo_router.DriverHookOwnershipError("foreign hook"),
                409,
                "foreign hook",
            ),
            (ValueError("invalid assignment"), 400, "invalid assignment"),
        ],
    )
    def test_reconcile_driver_hooks_maps_domain_errors(
        self,
        monkeypatch,
        error,
        status_code,
        detail,
    ):
        monkeypatch.setattr(
            linbo_router.LinboDriverManager,
            "reconcile_driver_hooks",
            _raise_error(error),
        )

        r = client.post(
            f"{BASE_URL}/linbo/drivers/hooks/reconcile",
            headers={"X-API-KEY": GLOBALADMIN.jwt},
        )

        assert r.status_code == status_code
        assert r.json()["detail"] == detail

    @pytest.mark.parametrize(
        "method,endpoint,payload",
        [
            ("get", "profiles", None),
            ("get", "images", None),
            ("get", "inventory", None),
            ("get", "inventory/pytest-client", None),
            ("get", "profiles/pytest-profile", None),
            (
                "post",
                "profiles",
                {"name": "pytest-profile", "vendor": "pytest", "products": ["pytest"]},
            ),
            (
                "post",
                "profiles/from-inventory",
                {"hostname": "pytest-client"},
            ),
            ("post", "hooks/reconcile", None),
            (
                "put",
                "profiles/pytest-profile/match",
                {"vendor": "pytest", "products": ["pytest"]},
            ),
            (
                "put",
                "profiles/pytest-profile/image",
                {"image": "pytest-image"},
            ),
            ("delete", "profiles/pytest-profile/image", None),
            ("delete", "profiles/pytest-profile", None),
        ],
    )
    @pytest.mark.parametrize("user", USERS[1:])
    def test_linbo_drivers_denied(self, method, endpoint, payload, user):
        r = client.request(
            method,
            f"{BASE_URL}/linbo/drivers/{endpoint}",
            headers={"X-API-KEY": user.jwt},
            json=payload,
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]
