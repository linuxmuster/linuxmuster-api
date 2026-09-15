"""
Scope of a x-host-key: which endpoints one key may reach.

The scope narrows an existing key, it never grants anything: every test here
checks what is refused, plus that a key without a scope keeps working exactly
as before.
"""

import pytest
from fastapi import HTTPException

from fastapi.testclient import TestClient

from main import app
import security.header as header_module
from security.scope import ScopeError, allows, parse_entry, report_unmatched


@pytest.fixture
def client():
    return TestClient(app)


# ── Parsing ──────────────────────────────────────────────────────────


def test_parse_splits_method_from_path():
    assert parse_entry("GET /linbo/hosts/pc01/status") == (
        "GET", ("linbo", "hosts", "pc01", "status")
    )


def test_parse_upper_cases_the_method():
    method, _ = parse_entry("get /devices/list/default-school")
    assert method == "GET"


def test_parse_keeps_a_trailing_slash_as_a_segment():
    # /users and /users/ are different routes in this API.
    assert parse_entry("GET /users/") == ("GET", ("users", ""))
    assert parse_entry("GET /users") == ("GET", ("users",))


@pytest.mark.parametrize("entry", [
    "GET",                          # no path
    "GET devices/list",             # path not absolute
    "GET /linbo/**/status",         # ** anywhere but last
])
def test_parse_rejects_malformed_entries(entry):
    with pytest.raises(ScopeError):
        parse_entry(entry)


# ── Matching ─────────────────────────────────────────────────────────


def test_no_scope_allows_everything():
    assert allows(None, "DELETE", "/users/olduser") is True
    assert allows("*", "DELETE", "/users/olduser") is True


def test_exact_entry_allows_only_that_path():
    scope = ["GET /linbo/hosts/pc01/status"]
    assert allows(scope, "GET", "/linbo/hosts/pc01/status") is True
    assert allows(scope, "GET", "/linbo/hosts/pc02/status") is False


def test_method_is_part_of_the_match():
    scope = ["GET /linbo/hosts/pc01/status"]
    assert allows(scope, "POST", "/linbo/hosts/pc01/status") is False
    assert allows(["* /linbo/hosts/pc01/status"], "POST", "/linbo/hosts/pc01/status") is True


def test_single_wildcard_spans_exactly_one_segment():
    scope = ["GET /linbo/hosts/*/status"]
    assert allows(scope, "GET", "/linbo/hosts/pc01/status") is True
    assert allows(scope, "GET", "/linbo/hosts/status") is False
    assert allows(scope, "GET", "/linbo/hosts/a/b/status") is False


def test_single_wildcard_does_not_match_an_empty_segment():
    # /devices/list/* must not open /devices/list/
    assert allows(["GET /devices/list/*"], "GET", "/devices/list/") is False


def test_double_wildcard_spans_the_rest_of_the_path():
    scope = ["GET /linbo/**"]
    assert allows(scope, "GET", "/linbo/images") is True
    assert allows(scope, "GET", "/linbo/hosts/pc01/status") is True
    # It stands for at least one segment, not for none.
    assert allows(scope, "GET", "/linbo") is False
    # And it stays inside its prefix.
    assert allows(scope, "GET", "/devices/list/default-school") is False


def test_several_entries_are_alternatives():
    scope = ["GET /linbo/hosts/*/status", "POST /linbo/sync/run"]
    assert allows(scope, "GET", "/linbo/hosts/pc01/status") is True
    assert allows(scope, "POST", "/linbo/sync/run") is True
    assert allows(scope, "POST", "/linbo/hosts/pc01/status") is False


def test_an_unparsable_entry_is_dropped_not_fatal():
    # The bad entry was already reported at startup; the good one still works.
    scope = ["nonsense", "GET /linbo/hosts/pc01/status"]
    assert allows(scope, "GET", "/linbo/hosts/pc01/status") is True
    assert allows(scope, "GET", "/users/") is False


def test_an_empty_scope_allows_nothing():
    assert allows([], "GET", "/linbo/hosts/pc01/status") is False


# ── check_host_header() ──────────────────────────────────────────────


@pytest.fixture
def ldap_user(monkeypatch):
    """Resolve any mapped user without touching LDAP."""

    monkeypatch.setattr(
        header_module.lr, "getvalues",
        lambda *args, **kwargs: {
            "sophomorixRole": "schooladministrator",
            "sophomorixSchoolname": "default-school",
            "distinguishedName": "CN=helpdesk,OU=default-school,DC=linuxmuster,DC=lan",
        },
    )


def _keys(scope):
    return {"helpdesk": {"secret": "s3cret", "user": "helpdesk", "ips": [], "scope": scope}}


def test_a_key_is_refused_outside_its_scope(ldap_user):
    with pytest.raises(HTTPException) as refused:
        header_module.check_host_header(
            "s3cret", "10.0.5.12", _keys(["GET /linbo/hosts/*/status"]), True,
            "DELETE", "/users/someone",
        )

    assert refused.value.status_code == 403


def test_a_key_passes_inside_its_scope(ldap_user):
    who = header_module.check_host_header(
        "s3cret", "10.0.5.12", _keys(["GET /linbo/hosts/*/status"]), True,
        "GET", "/linbo/hosts/pc01/status",
    )

    assert who.user == "helpdesk"
    assert who.role == "schooladministrator"


def test_a_key_without_a_scope_is_unaffected(ldap_user):
    keys = {"srv": {"secret": "s3cret", "user": "helpdesk", "ips": []}}

    who = header_module.check_host_header(
        "s3cret", "10.0.5.12", keys, True, "DELETE", "/users/someone",
    )

    assert who.user == "helpdesk"


def test_the_ip_check_still_runs_before_the_scope(ldap_user):
    keys = {"srv": {"secret": "s3cret", "user": "helpdesk", "ips": ["10.0.5.12"],
                    "scope": ["GET /linbo/hosts/*/status"]}}

    with pytest.raises(HTTPException) as refused:
        header_module.check_host_header(
            "s3cret", "192.168.0.1", keys, True, "GET", "/linbo/hosts/pc01/status",
        )

    assert refused.value.status_code == 401


# ── Startup report ───────────────────────────────────────────────────


ROUTES = [
    ("GET", "/users/"),
    ("GET", "/linbo/hosts/{hostname}/status"),
    ("POST", "/linbo/sync/run"),
]


def test_report_accepts_an_entry_matching_a_route_template():
    assert report_unmatched(["GET /linbo/hosts/pc01/status"], ROUTES) == []
    assert report_unmatched(["GET /linbo/hosts/*/status"], ROUTES) == []


def test_report_flags_a_missing_trailing_slash():
    # /users exists only as /users/: the likeliest typo, and a silent one.
    assert report_unmatched(["GET /users"], ROUTES) == ["GET /users"]


def test_report_flags_a_wrong_method():
    assert report_unmatched(["POST /users/"], ROUTES) == ["POST /users/"]


def test_report_flags_an_unparsable_entry():
    assert report_unmatched(["nonsense"], ROUTES) == ["nonsense"]


def test_report_says_nothing_about_an_unrestricted_key():
    assert report_unmatched(None, ROUTES) == []
    assert report_unmatched("*", ROUTES) == []


# ── Through a real request ───────────────────────────────────────────


@pytest.fixture
def host_key(monkeypatch):
    """
    Arm a scoped host key on the running app.

    The mapped user is a globaladministrator so that RoleChecker lets every
    route through: what is left refusing anything is the scope alone.
    """

    monkeypatch.setattr(
        header_module.lr, "getvalues",
        lambda *args, **kwargs: {
            "sophomorixRole": "globaladministrator",
            "sophomorixSchoolname": "global",
            "distinguishedName": "CN=helpdesk,DC=linuxmuster,DC=lan",
        },
    )

    def arm(scope):
        monkeypatch.setattr(app.state, "host_key_auth_enable", True, raising=False)
        monkeypatch.setattr(
            app.state, "host_keys",
            {"helpdesk": {"secret": "s3cret", "user": "helpdesk", "ips": [], "scope": scope}},
            raising=False,
        )
        return {"X-HOST-Key": "s3cret"}

    return arm


def test_a_scoped_key_reaches_the_route_it_names(host_key, client):
    # The scope is written without /v1, the request carries it: the prefix has
    # to be stripped between the two for anything to match at all.
    headers = host_key(["GET /schools/"])

    assert client.get("/v1/schools/", headers=headers).status_code == 200


def test_a_scoped_key_is_refused_elsewhere(host_key, client):
    headers = host_key(["GET /schools/"])

    assert client.get("/v1/users/", headers=headers).status_code == 403


def test_a_wildcard_scope_reaches_a_parameterised_route(host_key, client):
    headers = host_key(["GET /schools/*"])

    # Any school, without the admin having to know FastAPI's {school}.
    assert client.get("/v1/schools/default-school", headers=headers).status_code in (200, 404)
    assert client.get("/v1/users/", headers=headers).status_code == 403


def test_the_method_is_enforced_over_the_wire(host_key, client):
    headers = host_key(["POST /schools/"])

    assert client.get("/v1/schools/", headers=headers).status_code == 403


def test_a_key_without_a_scope_still_reaches_everything(host_key, client):
    headers = host_key(None)

    assert client.get("/v1/schools/", headers=headers).status_code == 200
    assert client.get("/v1/users/", headers=headers).status_code == 200
