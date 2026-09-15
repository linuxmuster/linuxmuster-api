"""
Scope of a x-host-key: which endpoints one key is allowed to reach.

Without a scope a host key gets the full LDAP role of the user it maps to,
over the whole API. A scope narrows that to a list of endpoints; it never
widens anything, the role check still runs behind it.

The scope is matched against the *concrete* request path, not the FastAPI
route template: an admin writes what they see on the wire, and a template
could not express "this one host" anyway, since `{hostname}` stands for all
of them. Two wildcards give back the breadth when it is wanted:

    GET /linbo/hosts/pc01/status      one host
    GET /linbo/hosts/*/status         every host
    GET /linbo/**                     every route under /linbo

The version prefix is left out: callers write `/devices/list/{school}` paths
without `/v1`, and check_authentication_header() strips it before matching.
"""

import logging


logger = logging.getLogger(__name__)

ONE = '*'
MANY = '**'
UNRESTRICTED = '*'


class ScopeError(ValueError):
    """A scope entry that cannot be understood."""


def _split(path):
    """Path to segments, keeping a trailing empty one: /users/ is not /users."""

    return tuple(path.split('/')[1:])


def parse_entry(entry):
    """
    Parse one "<METHOD> <path>" entry.

    :param entry: Raw entry as written in the configuration
    :type entry: str
    :return: Upper-cased method and the path split into segments
    :rtype: tuple
    :raises ScopeError: entry is not "<METHOD> <path>" with an absolute path
    """

    parts = str(entry).split(None, 1)

    if len(parts) != 2:
        raise ScopeError(f"expected '<METHOD> <path>', got {entry!r}")

    method, path = parts[0].upper(), parts[1].strip()

    if not path.startswith('/'):
        raise ScopeError(f"path must start with '/', got {entry!r}")

    segments = _split(path)

    if MANY in segments[:-1]:
        raise ScopeError(f"'{MANY}' is only allowed as the last element, got {entry!r}")

    return method, segments


def parse(raw_scope):
    """
    Parse a whole scope, dropping the entries that cannot be understood.

    Dropping rather than raising is deliberate: a malformed entry has already
    been reported at startup by report_unmatched(), and a key that stops
    working is a better outcome than an API that refuses to answer at all.

    :param raw_scope: Value of the `scope` field of one host key
    :type raw_scope: list | str | None
    :return: None if the key is unrestricted, else the parsed entries
    :rtype: list | None
    """

    if raw_scope is None or raw_scope == UNRESTRICTED:
        return None

    if isinstance(raw_scope, str):
        raw_scope = [raw_scope]

    parsed = []

    for entry in raw_scope:
        try:
            parsed.append(parse_entry(entry))
        except ScopeError as error:
            logger.warning(f"Ignoring host key scope entry: {error}")

    return parsed


def _segments_match(pattern, actual, template=False):
    """
    Match pattern segments against actual ones.

    :param template: Treat a `{param}` segment of `actual` as matching
                     anything, to check an entry against a route template
    :type template: bool
    """

    def one(expected, got):
        if expected == ONE:
            # A wildcard stands for a segment, not for its absence: /users/*
            # must not match /users/.
            return bool(got)
        if template and got.startswith('{') and got.endswith('}'):
            return True
        return expected == got

    if pattern and pattern[-1] == MANY:
        head = pattern[:-1]

        if len(actual) <= len(head):
            return False

        return all(one(expected, got) for expected, got in zip(head, actual))

    if len(pattern) != len(actual):
        return False

    return all(one(expected, got) for expected, got in zip(pattern, actual))


def allows(raw_scope, method, path):
    """
    Tell whether a scope lets a request through.

    :param raw_scope: Value of the `scope` field of one host key
    :type raw_scope: list | str | None
    :param method: HTTP method of the request
    :type method: str
    :param path: Request path, without the version prefix
    :type path: str
    :rtype: bool
    """

    parsed = parse(raw_scope)

    if parsed is None:
        return True

    segments = _split(path)
    method = method.upper()

    for allowed_method, pattern in parsed:
        if allowed_method not in (UNRESTRICTED, method):
            continue

        if _segments_match(pattern, segments):
            return True

    return False


def report_unmatched(raw_scope, routes):
    """
    Return the entries that match no route of the API.

    On an API this size a typo is the likeliest mistake, and it fails
    silently: the key keeps authenticating and every call is refused. An
    entry is reported either because it cannot be parsed, or because nothing
    it could ever match exists — a missing trailing slash is the usual cause,
    `/users` and `/users/` not being the same path.

    :param raw_scope: Value of the `scope` field of one host key
    :type raw_scope: list | str | None
    :param routes: Known routes as (method, path without version prefix)
    :type routes: iterable
    :return: The offending raw entries, in the order they were written
    :rtype: list
    """

    if raw_scope is None or raw_scope == UNRESTRICTED:
        return []

    if isinstance(raw_scope, str):
        raw_scope = [raw_scope]

    known = [(method.upper(), _split(path)) for method, path in routes]
    unmatched = []

    for entry in raw_scope:
        try:
            method, pattern = parse_entry(entry)
        except ScopeError:
            unmatched.append(entry)
            continue

        if not any(
            method in (UNRESTRICTED, route_method)
            and _segments_match(pattern, route_segments, template=True)
            for route_method, route_segments in known
        ):
            unmatched.append(entry)

    return unmatched
