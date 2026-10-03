from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routers_v1 import sessions
from security import AuthenticatedUser, check_authentication_header


class FakeLMNUser:
    """Records what the router writes in sophomorixSessions."""

    written = []

    def __init__(self, user, school=None):
        pass

    def setattr(self, data, add=False):
        FakeLMNUser.written.append(data['sophomorixSessions'])

    def delattr(self, data):
        pass


@pytest.fixture
def client(monkeypatch):
    FakeLMNUser.written = []
    monkeypatch.setattr(sessions, 'LMNUser', FakeLMNUser)

    session = SimpleNamespace(sid='sid1', name='test', members=['m10', 'm2', 'm5'])
    monkeypatch.setattr(
        sessions, 'get_user_or_404',
        lambda user, school: SimpleNamespace(lmnsessions=[session])
    )

    app = FastAPI()
    app.include_router(sessions.router, prefix="/v1")
    app.dependency_overrides[check_authentication_header] = lambda: AuthenticatedUser(
        dn="",
        user="global-admin",
        role="globaladministrator",
    )
    return TestClient(app)


def written_members():
    # sid;name;members;
    return FakeLMNUser.written[-1].split(';')[2].split(',')


def test_new_session_members_are_sorted_naturally(client):
    r = client.post("/v1/sessions/teacher/newsession", json={'users': ['m10', 'm2', 'm1']})

    assert r.status_code == 200
    assert written_members() == ['m1', 'm2', 'm10']


def test_added_members_are_sorted_naturally(client):
    r = client.post("/v1/sessions/teacher/sid1/members", json={'users': ['m1', 'm20']})

    assert r.status_code == 200
    assert written_members() == ['m1', 'm2', 'm5', 'm10', 'm20']


def test_remaining_members_are_sorted_naturally(client):
    r = client.request("DELETE", "/v1/sessions/teacher/sid1/members", json={'users': ['m5']})

    assert r.status_code == 204
    assert written_members() == ['m2', 'm10']
