"""
The printer writer must be built for the school of the caller.

LMNPrinter defaults to school='default-school', so an endpoint that forgets
the keyword silently writes in the wrong OU on a multi-school installation.
These tests pin the keyword down without needing a second school, by
capturing what the router passes to the constructor.
"""

from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from routers_v1 import printers


OTHER_SCHOOL = "second-school"


@pytest.fixture
def captured(monkeypatch):
    """Capture the arguments the router builds LMNPrinter with."""

    calls = []

    def fake_printer(cn, **kwargs):
        calls.append((cn, kwargs))
        return Mock()

    monkeypatch.setattr(printers, "LMNPrinter", fake_printer)
    return calls


@pytest.fixture
def joinable_printer(monkeypatch):
    """A joinable printer the caller is not a member of yet."""

    printer = Mock()
    printer.member = []
    printer.sophomorixJoinable = True
    monkeypatch.setattr(printers, "get_printer_or_404", lambda p, s: printer)
    monkeypatch.setattr(printers.lr, "getval", lambda *a, **k: [])
    return printer


def _who(school):
    who = Mock()
    who.school = school
    who.user = "teacher1"
    who.dn = f"CN=teacher1,OU=Teachers,OU={school},OU=SCHOOLS,DC=test"
    return who


def test_join_builds_the_writer_for_the_caller_school(captured, joinable_printer):
    printers.join_printer("drucker2", who=_who(OTHER_SCHOOL))

    assert len(captured) == 1
    cn, kwargs = captured[0]
    assert cn == "drucker2"
    assert kwargs.get("school") == OTHER_SCHOOL


def test_quit_builds_the_writer_for_the_caller_school(captured, monkeypatch):
    who = _who(OTHER_SCHOOL)
    printer = Mock()
    printer.member = [who.dn]
    monkeypatch.setattr(printers, "get_printer_or_404", lambda p, s: printer)
    monkeypatch.setattr(printers.lr, "getval", lambda *a, **k: [])

    printers.quit_printer("drucker2", who=who)

    assert len(captured) == 1
    cn, kwargs = captured[0]
    assert cn == "drucker2"
    assert kwargs.get("school") == OTHER_SCHOOL
