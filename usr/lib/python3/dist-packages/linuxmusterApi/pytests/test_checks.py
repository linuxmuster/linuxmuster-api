import pytest
from types import SimpleNamespace
from fastapi import HTTPException

from utils.checks import get_group_or_404, require_school


class TestGetGroupOr404:
    def test_group_not_found_is_404(self, monkeypatch):
        class Empty:
            cn = None

        monkeypatch.setattr("utils.checks.lr.get", lambda *a, **k: Empty())

        with pytest.raises(HTTPException) as exc_info:
            get_group_or_404("somegroup", "default-school")

        assert exc_info.value.status_code == 404


@require_school
def _dummy_endpoint(school='', who=None):
    return 'ok'


class TestRequireSchool:
    def test_passes_through_when_who_school_not_global(self):
        who = SimpleNamespace(school='default-school')
        assert _dummy_endpoint(school='', who=who) == 'ok'

    def test_raises_400_when_global_and_no_school(self):
        who = SimpleNamespace(school='global')
        with pytest.raises(HTTPException) as exc_info:
            _dummy_endpoint(school='', who=who)
        assert exc_info.value.status_code == 400

    def test_raises_404_when_global_and_invalid_school(self, monkeypatch):
        monkeypatch.setattr("utils.checks.lr.getval", lambda *a, **k: ['default-school'])
        who = SimpleNamespace(school='global')
        with pytest.raises(HTTPException) as exc_info:
            _dummy_endpoint(school='bogus-school', who=who)
        assert exc_info.value.status_code == 404

    def test_passes_through_when_global_and_valid_school(self, monkeypatch):
        monkeypatch.setattr("utils.checks.lr.getval", lambda *a, **k: ['default-school'])
        who = SimpleNamespace(school='global')
        assert _dummy_endpoint(school='default-school', who=who) == 'ok'
