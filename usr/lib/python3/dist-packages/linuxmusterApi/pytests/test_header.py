"""
Unit tests for security/header.py's handling of a not-yet-provisioned domain
(fresh install, linuxmuster-setup not run yet): lr.getvalues() then raises
LdapNotProvisionedError, which must surface as a clear 503 instead of an
unhandled 500.
"""

import jwt
import pytest
from fastapi import HTTPException

from linuxmusterTools.common import LdapNotProvisionedError
import security.header as header_module
from security.header import check_user_header, check_host_header

SECRET = 'test-secret'


def make_jwt(user='jdoe'):
    return jwt.encode({'user': user}, SECRET, algorithm='HS512')


class TestCheckUserHeaderProvisioning:

    def test_raises_503_when_ldap_not_provisioned(self, monkeypatch):
        monkeypatch.setattr(
            header_module.lr, 'getvalues',
            lambda *a, **k: (_ for _ in ()).throw(LdapNotProvisionedError('setup.ini missing')),
        )

        with pytest.raises(HTTPException) as excinfo:
            check_user_header(make_jwt(), SECRET)

        assert excinfo.value.status_code == 503
        assert excinfo.value.detail == "linuxmuster is not provisioned yet"

    def test_returns_user_when_provisioned(self, monkeypatch):
        monkeypatch.setattr(
            header_module.lr, 'getvalues',
            lambda *a, **k: {
                'sophomorixRole': 'teacher',
                'sophomorixSchoolname': 'default-school',
                'distinguishedName': 'CN=jdoe,DC=test',
            },
        )

        result = check_user_header(make_jwt(), SECRET)

        assert result.user == 'jdoe'
        assert result.role == 'teacher'


class TestCheckHostHeaderProvisioning:

    KEYS = {'server1': {'secret': 'host-secret', 'user': 'sophomorix', 'ips': []}}

    def test_raises_503_when_ldap_not_provisioned(self, monkeypatch):
        monkeypatch.setattr(
            header_module.lr, 'getvalues',
            lambda *a, **k: (_ for _ in ()).throw(LdapNotProvisionedError('setup.ini missing')),
        )

        with pytest.raises(HTTPException) as excinfo:
            check_host_header('host-secret', '10.0.0.1', self.KEYS, True)

        assert excinfo.value.status_code == 503
        assert excinfo.value.detail == "linuxmuster is not provisioned yet"

    def test_returns_user_when_provisioned(self, monkeypatch):
        monkeypatch.setattr(
            header_module.lr, 'getvalues',
            lambda *a, **k: {
                'sophomorixRole': 'globaladministrator',
                'sophomorixSchoolname': 'default-school',
                'distinguishedName': 'CN=sophomorix,DC=test',
            },
        )

        result = check_host_header('host-secret', '10.0.0.1', self.KEYS, True)

        assert result.user == 'sophomorix'
        assert result.role == 'globaladministrator'
