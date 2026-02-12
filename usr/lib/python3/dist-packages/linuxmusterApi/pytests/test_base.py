import json
import sys
from base64 import b64encode
from fastapi.testclient import TestClient

from .jwtapi import jwt_get
from .credentials import BASE_URL, LOCAL_API_PATH, USERS

sys.path.append(LOCAL_API_PATH)
from main import app

TEST_USER = USERS[0]
LOGIN = TEST_USER.cn
PASSWORD = TEST_USER.password
BASIC_TOKEN = b64encode(f"{LOGIN}:{PASSWORD}".encode('utf-8')).decode("ascii")
WRONG_TOKEN = b64encode(f"{LOGIN}:{PASSWORD[:-1]}".encode('utf-8')).decode("ascii")
JWT = jwt_get(LOGIN)

client = TestClient(app)

class TestAuth:
    def test_get_jwt_token(self):
        r = client.get(f"{BASE_URL}/auth", headers={"Authorization": f"Basic {BASIC_TOKEN}"})
        jwt = r.content.decode("utf-8").strip('"')

        assert r.status_code == 200
        assert jwt == JWT

    def test_wrong_token(self):
        r = client.get(f"{BASE_URL}/auth", headers={"Authorization": f"Basic {WRONG_TOKEN}"})

        assert r.status_code == 401
        assert "Wrong credentials" in r.content.decode("utf-8")

    def test_whoami(self):
        r = client.get(f"{BASE_URL}/auth/whoami", headers={"X-API-KEY": JWT})
        data = json.loads(r.content.decode("utf-8"))

        assert r.status_code == 200
        assert data["user"] == LOGIN
        assert data["role"] == TEST_USER.role
        assert data["school"] == TEST_USER.school

    def test_whoami_wrong_jwt(self):
        r = client.get(f"{BASE_URL}/auth/whoami", headers={"X-API-KEY": JWT[:-1]})
        data = json.loads(r.content.decode("utf-8"))

        assert r.status_code == 401
        assert data["detail"] == "Invalid API Key"





