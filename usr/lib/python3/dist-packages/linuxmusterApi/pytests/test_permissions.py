import pytest

from security import BasicChecker, AuthenticatedUser, check_print_permissions


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


def _ldap(monkeypatch, role, school='default-school'):
    monkeypatch.setattr("security.permissions.lr.getvalues",
                        lambda *a, **k: {'sophomorixRole': role, 'sophomorixSchoolname': school})


@pytest.mark.parametrize("identity_role, target_role, expected", ACCESS)
def test_role_rank_access(monkeypatch, identity_role, target_role, expected):
    _ldap(monkeypatch, target_role)
    assert BasicChecker([])._check_role_permissions(_who(identity_role), 'target') is expected


@pytest.mark.parametrize("identity_role, target_role", [
    ('schooladministrator', 'teacher'),
    ('schooladministrator', 'student'),
    ('teacher', 'student'),
    ('teacher', 'examuser'),
])
def test_other_school_is_out_of_reach(monkeypatch, identity_role, target_role):
    _ldap(monkeypatch, target_role, school='other-school')
    assert BasicChecker([])._check_role_permissions(_who(identity_role), 'target') is False


def test_globaladministrator_reaches_other_schools(monkeypatch):
    _ldap(monkeypatch, 'student', school='other-school')
    assert BasicChecker([])._check_role_permissions(_who('globaladministrator'), 'target') is True


@pytest.mark.parametrize("role", ['schooladministrator', 'teacher'])
def test_same_role_own_account_is_allowed(monkeypatch, role):
    _ldap(monkeypatch, role)
    assert BasicChecker([])._check_role_permissions(_who(role), 'caller') is True


# Users whose password may be printed: (identity role, target role, target school)
PRINT = [
    ('globaladministrator',  'student',              'other-school', True),
    ('globaladministrator',  'schooladministrator',  'default-school', False),
    ('schooladministrator',  'teacher',              'default-school', True),
    ('schooladministrator',  'parent',               'default-school', True),
    ('schooladministrator',  'student',              'other-school', False),
    ('schooladministrator',  'schooladministrator',  'default-school', False),
    ('teacher',              'student',              'default-school', True),
    ('teacher',              'examuser',             'default-school', True),
    ('teacher',              'student',              'other-school', False),
    ('teacher',              'teacher',              'default-school', False),
    ('teacher',              'parent',               'default-school', False),
    ('teacher',              'staff',                'default-school', False),
    ('teacher',              None,                   None, False),
]


@pytest.mark.parametrize("identity_role, target_role, target_school, expected", PRINT)
def test_print_permissions(monkeypatch, identity_role, target_role, target_school, expected):
    _ldap(monkeypatch, target_role, school=target_school)
    assert (check_print_permissions(_who(identity_role), {'target'}) == {'target'}) is expected


def test_print_permissions_never_own_password(monkeypatch):
    _ldap(monkeypatch, 'teacher')
    assert check_print_permissions(_who('teacher'), {'caller'}) == set()
