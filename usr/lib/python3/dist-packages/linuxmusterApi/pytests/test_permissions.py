import pytest

from security import BasicChecker, AuthenticatedUser


# Expected access of the identity role (rows) to another user of the target
# role (columns): only users of a strictly lower rank, never the same rank.
# Parents and staff have the same rank as teachers, but no access to anybody.
ACCESS = [
    # identity,               target,                expected
    ('globaladministrator',  'globaladministrator',  True),
    ('globaladministrator',  'student',              True),
    ('schooladministrator',  'schooladministrator',  False),
    ('schooladministrator',  'teacher',              True),
    ('schooladministrator',  'parent',               True),
    ('schooladministrator',  'staff',                True),
    ('schooladministrator',  'student',              True),
    ('schooladministrator',  'examuser',             True),
    ('teacher',              'globaladministrator',  False),
    ('teacher',              'schooladministrator',  False),
    ('teacher',              'teacher',              False),
    ('teacher',              'parent',               False),
    ('teacher',              'staff',                False),
    ('teacher',              'student',              True),
    ('teacher',              'examuser',             True),
    ('teacher',              'unknownrole',          False),
    ('parent',               'student',              False),
    ('parent',               'parent',               False),
    ('staff',                'student',              False),
    ('staff',                'staff',                False),
    ('student',              'student',              False),
]


def _who(role):
    return AuthenticatedUser(dn='', user='caller', role=role, school='default-school')


@pytest.mark.parametrize("identity_role, target_role, expected", ACCESS)
def test_role_rank_access(monkeypatch, identity_role, target_role, expected):
    monkeypatch.setattr("security.permissions.lr.getval", lambda *a, **k: target_role)
    assert BasicChecker([])._check_role_permissions(_who(identity_role), 'target') is expected


@pytest.mark.parametrize("role", ['schooladministrator', 'teacher'])
def test_same_role_own_account_is_allowed(monkeypatch, role):
    monkeypatch.setattr("security.permissions.lr.getval", lambda *a, **k: role)
    assert BasicChecker([])._check_role_permissions(_who(role), 'caller') is True
