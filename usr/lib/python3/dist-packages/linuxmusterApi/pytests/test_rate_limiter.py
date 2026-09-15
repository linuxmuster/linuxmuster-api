import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from security.rate_limiter import RateLimiter, request_counters


def _request(ip, path='/v1/auth/', **rate_limit):
    """A request as the limiter reads it: client address, path, app settings."""

    return SimpleNamespace(
        client=SimpleNamespace(host=ip),
        url=SimpleNamespace(path=path),
        app=SimpleNamespace(state=SimpleNamespace(rate_limit=rate_limit)),
    )


class TestRateLimiterLoopbackExemption:

    def test_loopback_ipv4_is_never_counted(self):
        limiter = RateLimiter(requests_limit=1, time_window=60)
        request = _request('127.0.0.1')

        for _ in range(5):
            assert asyncio.run(limiter(request)) is True

        assert request_counters == {}

    def test_loopback_ipv6_is_never_counted(self):
        limiter = RateLimiter(requests_limit=1, time_window=60)
        request = _request('::1')

        for _ in range(5):
            assert asyncio.run(limiter(request)) is True

    def test_external_ip_is_still_limited(self):
        limiter = RateLimiter(requests_limit=1, time_window=60)
        request = _request('10.0.0.5')

        assert asyncio.run(limiter(request)) is True
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(limiter(request))
        assert exc_info.value.status_code == 429


class TestRateLimiterWhitelist:

    def test_a_whitelisted_ip_is_never_counted(self):
        limiter = RateLimiter(requests_limit=1, time_window=60)
        request = _request('10.0.0.5', whitelist=['10.0.0.5'])

        for _ in range(5):
            assert asyncio.run(limiter(request)) is True

        assert request_counters == {}

    def test_an_ip_outside_the_whitelist_is_still_limited(self):
        limiter = RateLimiter(requests_limit=1, time_window=60)
        request = _request('10.0.0.6', whitelist=['10.0.0.5'])

        assert asyncio.run(limiter(request)) is True
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(limiter(request))
        assert exc_info.value.status_code == 429

    def test_a_single_address_may_be_written_as_a_string(self):
        limiter = RateLimiter(requests_limit=1, time_window=60)
        request = _request('10.0.0.5', whitelist='10.0.0.5')

        for _ in range(3):
            assert asyncio.run(limiter(request)) is True

    def test_loopback_stays_exempt_with_a_whitelist_set(self):
        limiter = RateLimiter(requests_limit=1, time_window=60)
        request = _request('127.0.0.1', whitelist=['10.0.0.5'])

        for _ in range(3):
            assert asyncio.run(limiter(request)) is True


class TestRateLimiterConfiguredThresholds:

    def test_the_configured_limit_overrides_the_decorator(self):
        limiter = RateLimiter(requests_limit=1, time_window=60)
        request = _request('10.0.0.7', requests=3)

        for _ in range(3):
            assert asyncio.run(limiter(request)) is True
        with pytest.raises(HTTPException):
            asyncio.run(limiter(request))

    def test_the_configured_window_overrides_the_decorator(self):
        # The decorator would forget the counter at once; the configuration
        # keeps it for an hour, so a call ten seconds later is still counted.
        limiter = RateLimiter(requests_limit=1, time_window=0)
        request = _request('10.0.0.8', window=3600)

        assert asyncio.run(limiter(request)) is True
        request_counters['10.0.0.8:/v1/auth/']['timestamp'] -= 10

        with pytest.raises(HTTPException):
            asyncio.run(limiter(request))

    def test_zero_requests_disables_the_limiter(self):
        # Refusing every single call is not what `requests: 0` means.
        limiter = RateLimiter(requests_limit=5, time_window=60)
        request = _request('10.0.0.9', requests=0)

        for _ in range(10):
            assert asyncio.run(limiter(request)) is True

        assert request_counters == {}

    def test_no_configuration_keeps_the_decorator_values(self):
        limiter = RateLimiter(requests_limit=2, time_window=60)
        request = _request('10.0.0.10')

        for _ in range(2):
            assert asyncio.run(limiter(request)) is True
        with pytest.raises(HTTPException):
            asyncio.run(limiter(request))
