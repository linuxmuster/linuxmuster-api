import sys
import json
from fastapi.testclient import TestClient

from .credentials import *


sys.path.append(LOCAL_API_PATH)
from main import app

client = TestClient(app)
USERS = [GLOBALADMIN, SCHOOLADMIN, TEACHER, STUDENT, STAFF, PARENT]

class TestAuth:
    def test_get_jwt_token(self):
        for user in USERS:
            r = client.get(f"{BASE_URL}/auth", headers={"Authorization": f"Basic {user.basic_token}"})
            jwt = r.content.decode("utf-8").strip('"')

            assert r.status_code == 200
            assert jwt == user.jwt

    def test_wrong_token(self):
        for user in USERS:
            r = client.get(f"{BASE_URL}/auth", headers={"Authorization": f"Basic {user.wrongbasic_token}"})

            assert r.status_code == 401
            assert "Wrong credentials" in r.content.decode("utf-8")

    def test_whoami(self):
        for user in USERS:
            r = client.get(f"{BASE_URL}/auth/whoami", headers={"X-API-KEY": user.jwt})
            data = json.loads(r.content.decode("utf-8"))

            assert r.status_code == 200
            assert data["user"] == user.cn
            assert data["role"] == user.role
            assert data["school"] == user.school

    def test_whoami_wrong_jwt(self):
        for user in USERS:
            r = client.get(f"{BASE_URL}/auth/whoami", headers={"X-API-KEY": user.wrongjwt})
            data = json.loads(r.content.decode("utf-8"))

            assert r.status_code == 401
            assert data["detail"] == "Invalid API Key"





