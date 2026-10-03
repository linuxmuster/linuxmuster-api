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


import base64

from fastapi import Depends, FastAPI
from fastapi.security import HTTPBasic
from fastapi.testclient import TestClient

from security.basic_auth import BASIC_AUTH


def make_client(dependency=BASIC_AUTH):
    app = FastAPI()

    @app.get('/credentials')
    def credentials(credentials: HTTPBasicCredentials = Depends(dependency)):
        return {'username': credentials.username, 'password': credentials.password}

    return TestClient(app)


def basic(raw):
    return {'Authorization': 'Basic ' + base64.b64encode(raw).decode()}


class TestUTF8HTTPBasic:
    """
    The credentials must reach check_password() whatever their characters:
    Samba accepts ä, ß, € or an emoji in a password.
    """

    @pytest.mark.parametrize('password', ['äöüß123Abc', 'Paß§word1', '€uro123Ab', '😀Smile123'])
    def test_utf8_password_is_decoded(self, password):
        r = make_client().get('/credentials', headers=basic(f'jdoe:{password}'.encode('utf-8')))

        assert r.status_code == 200
        assert r.json() == {'username': 'jdoe', 'password': password}

    def test_latin1_password_is_decoded(self):
        # What requests sends for str credentials: ä then ö is no valid
        # UTF-8, so the Latin-1 fallback applies.
        r = make_client().get('/credentials', headers=basic('jdoe:äöüß123Abc'.encode('latin-1')))

        assert r.status_code == 200
        assert r.json() == {'username': 'jdoe', 'password': 'äöüß123Abc'}

    def test_latin1_bytes_which_are_valid_utf8_are_read_as_utf8(self):
        # The limit of the fallback: ß§ in Latin-1 is DF A7, a valid UTF-8
        # sequence (U+07E7), so the password arrives wrong.
        r = make_client().get('/credentials', headers=basic('jdoe:Paß§word1'.encode('latin-1')))

        assert r.json()['password'] == 'Pa\u07e7word1'

    def test_password_may_contain_a_colon(self):
        r = make_client().get('/credentials', headers=basic('jdoe:a:ß'.encode('utf-8')))

        assert r.json() == {'username': 'jdoe', 'password': 'a:ß'}

    @pytest.mark.parametrize('headers', [
        {},
        {'Authorization': 'Bearer abc'},
        {'Authorization': 'Basic !!!not-base64'},
        basic(b'no-separator'),
    ])
    def test_errors_are_answered_like_fastapi(self, headers):
        # Same status, detail and WWW-Authenticate header as FastAPI's own
        # HTTPBasic, for every malformed request.
        ours = make_client().get('/credentials', headers=headers)
        fastapi = make_client(HTTPBasic()).get('/credentials', headers=headers)

        assert ours.status_code == fastapi.status_code == 401
        assert ours.json() == fastapi.json()
        assert ours.headers.get('www-authenticate') == fastapi.headers.get('www-authenticate')

    def test_ascii_credentials_are_decoded_like_fastapi(self):
        headers = basic(b'jdoe:Muster!')

        ours = make_client().get('/credentials', headers=headers)
        fastapi = make_client(HTTPBasic()).get('/credentials', headers=headers)

        assert ours.json() == fastapi.json() == {'username': 'jdoe', 'password': 'Muster!'}
