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
_need_group_and_schoolclass = pytest.mark.skipif(
    'UNCONFIGURED' in (GROUP, SCHOOLCLASS),
    reason="GROUP and SCHOOLCLASS not set in credentials.py"
)


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
    def test_post_group_membergroups_denied(self, user):
        r = client.post(
            f"{BASE_URL}/groups/{GROUP}/membergroups",
            headers={"X-API-KEY": user.jwt},
            json={"groups": []}
        )
        assert r.status_code == 401
        assert 'Permission denied' in r.json()["detail"]

    @pytest.mark.parametrize("user", USERS[2:])
    def test_delete_group_membergroups_denied(self, user):
        r = client.request(
            "DELETE",
            f"{BASE_URL}/groups/{GROUP}/membergroups",
            headers={"X-API-KEY": user.jwt},
            json={"groups": []}
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


@_need_mgmt
class TestManagementGroupMembers:
    """
    Exercises the actual add/remove logic (GroupManager, via Samba's SamDB)
    behind /managementgroups/{group}/members, not just permission checks.
    STUDENT's membership in MGMT_GROUP is snapshotted before and restored
    after every test, since the shared test LDAP may already have it in
    either state.
    """

    @staticmethod
    def _members():
        r = client.get(f"{BASE_URL}/managementgroups/{MGMT_GROUP}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        return r.json()['member']

    @classmethod
    def _is_member(cls, cn):
        return any(m.startswith(f'CN={cn},') for m in cls._members())

    @staticmethod
    def _add(user_jwt, users, school=None):
        return client.post(
            f"{BASE_URL}/managementgroups/{MGMT_GROUP}/members",
            headers={"X-API-KEY": user_jwt},
            json={"users": users},
            params={"school": school} if school else {},
        )

    @staticmethod
    def _remove(user_jwt, users, school=None):
        return client.request(
            "DELETE",
            f"{BASE_URL}/managementgroups/{MGMT_GROUP}/members",
            headers={"X-API-KEY": user_jwt},
            json={"users": users},
            params={"school": school} if school else {},
        )

    @pytest.fixture(autouse=True)
    def _restore_student_membership(self):
        was_member = self._is_member(STUDENT.cn)
        yield
        is_member = self._is_member(STUDENT.cn)
        if was_member and not is_member:
            self._add(GLOBALADMIN.jwt, [STUDENT.cn], school="default-school")
        elif not was_member and is_member:
            self._remove(GLOBALADMIN.jwt, [STUDENT.cn], school="default-school")

    def test_post_then_delete_member_sa(self):
        assert self._add(SCHOOLADMIN.jwt, [STUDENT.cn]).status_code == 200
        assert self._is_member(STUDENT.cn)

        assert self._remove(SCHOOLADMIN.jwt, [STUDENT.cn]).status_code == 204
        assert not self._is_member(STUDENT.cn)

    def test_post_member_idempotent(self):
        # LDAP code 68 ("already a member") must be swallowed, not raised.
        assert self._add(SCHOOLADMIN.jwt, [STUDENT.cn]).status_code == 200
        assert self._add(SCHOOLADMIN.jwt, [STUDENT.cn]).status_code == 200
        assert self._is_member(STUDENT.cn)

    def test_delete_member_idempotent(self):
        # Removing a member who isn't (or is no longer) in the group must not error.
        self._remove(SCHOOLADMIN.jwt, [STUDENT.cn])
        assert self._remove(SCHOOLADMIN.jwt, [STUDENT.cn]).status_code == 204
        assert not self._is_member(STUDENT.cn)

    def test_post_member_ga_requires_school(self):
        # who.school == 'global': no school given -> 400, nothing done.
        assert self._add(GLOBALADMIN.jwt, [STUDENT.cn]).status_code == 400

    def test_post_member_ga_with_school(self):
        assert self._add(GLOBALADMIN.jwt, [STUDENT.cn], school="default-school").status_code == 200
        assert self._is_member(STUDENT.cn)

    def test_post_member_ga_unknown_school_404(self):
        assert self._add(GLOBALADMIN.jwt, [STUDENT.cn], school="not-a-real-school").status_code == 404

    def test_post_member_sa_other_school_forbidden(self):
        # school-administrators can't act on a school other than their own.
        assert self._add(SCHOOLADMIN.jwt, [STUDENT.cn], school="some-other-school").status_code == 403

    def test_post_member_unknown_group_404(self):
        r = client.post(
            f"{BASE_URL}/managementgroups/not-a-real-group/members",
            headers={"X-API-KEY": SCHOOLADMIN.jwt},
            json={"users": [STUDENT.cn]},
        )
        assert r.status_code == 404

    def test_post_member_unknown_user_404(self):
        # Regression check: GroupManager.add_members() used to swallow every
        # error, not just the benign "already a member" one, so this used to
        # report success even though nothing was added.
        # Uses GLOBALADMIN: UserListChecker validates each target user's role
        # for school-admins/teachers (rejecting an unknown user with a 401
        # before the endpoint even runs), but skips that check entirely for
        # global-administrators, so this is the one role that actually
        # reaches GroupManager.add_members() with an unresolvable member.
        r = self._add(GLOBALADMIN.jwt, ["not-a-real-user-xyz"], school="default-school")
        assert r.status_code == 404
        assert not self._is_member("not-a-real-user-xyz")


@_need_group_and_schoolclass
class TestGroupMembergroups:
    """
    Exercises nesting a schoolclass in GROUP behind /groups/{group}/membergroups,
    and the membergroups attribute when creating or updating a group.
    SCHOOLCLASS is removed from GROUP after every test if it was not a member
    before, and the temporary group is deleted.
    """

    TMP_GROUP = 'zz-pytest-membergroups'

    @staticmethod
    def _members(group):
        r = client.get(f"{BASE_URL}/groups/{group}", headers={"X-API-KEY": GLOBALADMIN.jwt})
        return r.json()['member'] if r.status_code == 200 else []

    @classmethod
    def _is_nested(cls, group, schoolclass):
        return any(m.startswith(f'CN={schoolclass},') for m in cls._members(group))

    @staticmethod
    def _add(user_jwt, groups, school=None):
        return client.post(
            f"{BASE_URL}/groups/{GROUP}/membergroups",
            headers={"X-API-KEY": user_jwt},
            json={"groups": groups},
            params={"school": school} if school else {},
        )

    @staticmethod
    def _remove(user_jwt, groups, school=None):
        return client.request(
            "DELETE",
            f"{BASE_URL}/groups/{GROUP}/membergroups",
            headers={"X-API-KEY": user_jwt},
            json={"groups": groups},
            params={"school": school} if school else {},
        )

    @pytest.fixture(autouse=True)
    def _restore_membergroups(self):
        was_nested = self._is_nested(GROUP, SCHOOLCLASS)
        yield
        if not was_nested and self._is_nested(GROUP, SCHOOLCLASS):
            self._remove(GLOBALADMIN.jwt, [SCHOOLCLASS], school=SCHOOL)
        client.delete(f"{BASE_URL}/groups/{self.TMP_GROUP}", headers={"X-API-KEY": SCHOOLADMIN.jwt})

    def test_post_then_delete_membergroup_sa(self):
        assert self._add(SCHOOLADMIN.jwt, [SCHOOLCLASS]).status_code == 200
        assert self._is_nested(GROUP, SCHOOLCLASS)

        assert self._remove(SCHOOLADMIN.jwt, [SCHOOLCLASS]).status_code == 204
        assert not self._is_nested(GROUP, SCHOOLCLASS)

    def test_direct_members_stay_when_a_membergroup_is_removed(self):
        before = [m for m in self._members(GROUP) if not m.startswith(f'CN={SCHOOLCLASS},')]
        self._add(SCHOOLADMIN.jwt, [SCHOOLCLASS])
        self._remove(SCHOOLADMIN.jwt, [SCHOOLCLASS])

        assert sorted(self._members(GROUP)) == sorted(before)

    def test_post_membergroup_idempotent(self):
        assert self._add(SCHOOLADMIN.jwt, [SCHOOLCLASS]).status_code == 200
        assert self._add(SCHOOLADMIN.jwt, [SCHOOLCLASS]).status_code == 200
        assert self._is_nested(GROUP, SCHOOLCLASS)

    def test_delete_membergroup_idempotent(self):
        self._remove(SCHOOLADMIN.jwt, [SCHOOLCLASS])
        assert self._remove(SCHOOLADMIN.jwt, [SCHOOLCLASS]).status_code == 204

    def test_post_membergroup_ga_requires_school(self):
        assert self._add(GLOBALADMIN.jwt, [SCHOOLCLASS]).status_code == 400

    def test_post_membergroup_ga_with_school(self):
        assert self._add(GLOBALADMIN.jwt, [SCHOOLCLASS], school=SCHOOL).status_code == 200
        assert self._is_nested(GROUP, SCHOOLCLASS)

    def test_post_membergroup_sa_other_school_forbidden(self):
        assert self._add(SCHOOLADMIN.jwt, [SCHOOLCLASS], school="some-other-school").status_code == 403

    def test_post_empty_membergroups_400(self):
        assert self._add(SCHOOLADMIN.jwt, []).status_code == 400

    def test_post_unknown_membergroup_404_and_nothing_written(self):
        before = self._members(GROUP)
        r = self._add(SCHOOLADMIN.jwt, [SCHOOLCLASS, "not-a-real-group-xyz"])

        assert r.status_code == 404
        assert "not-a-real-group-xyz" in r.json()["detail"]
        # Every name is resolved first: the valid one must not have been written either.
        assert sorted(self._members(GROUP)) == sorted(before)

    def test_post_group_into_itself_400(self):
        r = self._add(SCHOOLADMIN.jwt, [GROUP])

        assert r.status_code == 400
        assert "member of itself" in r.json()["detail"]

    def test_delete_unknown_membergroup_404(self):
        assert self._remove(SCHOOLADMIN.jwt, ["not-a-real-group-xyz"]).status_code == 404

    def test_create_group_with_membergroups(self):
        r = client.post(
            f"{BASE_URL}/groups/{self.TMP_GROUP}",
            headers={"X-API-KEY": SCHOOLADMIN.jwt},
            json={"membergroups": [SCHOOLCLASS]},
        )

        assert r.status_code == 200
        assert self._is_nested(self.TMP_GROUP, SCHOOLCLASS)

    def test_create_group_with_unknown_membergroup_creates_nothing(self):
        r = client.post(
            f"{BASE_URL}/groups/{self.TMP_GROUP}",
            headers={"X-API-KEY": SCHOOLADMIN.jwt},
            json={"membergroups": ["not-a-real-group-xyz"]},
        )

        assert r.status_code == 404
        assert client.get(f"{BASE_URL}/groups/{self.TMP_GROUP}", headers={"X-API-KEY": SCHOOLADMIN.jwt}).status_code == 404

    def test_patch_group_adds_membergroups(self):
        r = client.patch(
            f"{BASE_URL}/groups/{GROUP}",
            headers={"X-API-KEY": SCHOOLADMIN.jwt},
            json={"membergroups": [SCHOOLCLASS]},
        )

        assert r.status_code == 200
        assert self._is_nested(GROUP, SCHOOLCLASS)
