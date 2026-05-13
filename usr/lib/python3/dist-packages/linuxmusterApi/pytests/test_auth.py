import sys
import json
import jwt
import pytest
from fastapi.testclient import TestClient

from .credentials import *

sys.path.append(LOCAL_API_PATH)
from main import app


client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]

class TestAuth:
    @pytest.mark.parametrize("user", USERS)
    def test_get_jwt_token(self, user):
        r = client.get(f"{BASE_URL}/auth", headers={"Authorization": f"Basic {user.basic_token}"})
        assert r.status_code == 200

        token = r.content.decode("utf-8").strip('"')
        actual = jwt.decode(token, options={"verify_signature": False})
        expected = jwt.decode(user.jwt, options={"verify_signature": False})
        for key in ['user', 'role', 'dn', 'school']:
            assert actual[key] == expected[key]
        assert 'exp' in actual

    @pytest.mark.parametrize("user", USERS)
    def test_wrong_token(self, user):
        r = client.get(f"{BASE_URL}/auth", headers={"Authorization": f"Basic {user.wrongbasic_token}"})

        assert r.status_code == 401
        assert "Wrong credentials" in r.content.decode("utf-8")

    @pytest.mark.parametrize("user", USERS)
    def test_whoami(self, user):
        r = client.get(f"{BASE_URL}/auth/whoami", headers={"X-API-KEY": user.jwt})
        data = json.loads(r.content.decode("utf-8"))

        assert r.status_code == 200
        assert data["user"] == user.cn
        assert data["role"] == user.role
        assert data["school"] == user.school

    @pytest.mark.parametrize("user", USERS)
    def test_whoami_wrong_jwt(self, user):
        r = client.get(f"{BASE_URL}/auth/whoami", headers={"X-API-KEY": user.wrongjwt})
        data = json.loads(r.content.decode("utf-8"))

        assert r.status_code == 401
        assert data["detail"] == "Invalid API Key"





