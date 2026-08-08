"""
Unit tests for security/basic_auth.py's handling of a not-yet-provisioned
domain (fresh install, linuxmuster-setup not run yet): lr.get() then raises
LdapNotProvisionedError, which must surface as a clear 503 instead of the
generic "malformated username" 400.
"""

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPBasicCredentials

from linuxmusterTools.common import LdapNotProvisionedError
import security.basic_auth as basic_auth_module
from security.basic_auth import BasicAuthChecker

CREDENTIALS = HTTPBasicCredentials(username='jdoe', password='secret')


class TestBasicAuthCheckerProvisioning:

    def test_raises_503_when_ldap_not_provisioned(self, monkeypatch):
        monkeypatch.setattr(
            basic_auth_module.lr, 'get',
            lambda *a, **k: (_ for _ in ()).throw(LdapNotProvisionedError('setup.ini missing')),
        )

        with pytest.raises(HTTPException) as excinfo:
            BasicAuthChecker()(request=None, credentials=CREDENTIALS)

        assert excinfo.value.status_code == 503
        assert excinfo.value.detail == "linuxmuster is not provisioned yet"

    def test_still_returns_400_on_other_lookup_errors(self, monkeypatch):
        monkeypatch.setattr(
            basic_auth_module.lr, 'get',
            lambda *a, **k: (_ for _ in ()).throw(KeyError('sophomorixRole')),
        )

        with pytest.raises(HTTPException) as excinfo:
            BasicAuthChecker()(request=None, credentials=CREDENTIALS)

        assert excinfo.value.status_code == 400
