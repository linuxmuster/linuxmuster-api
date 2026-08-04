import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from security.rate_limiter import RateLimiter, request_counters


def _request(ip, path='/v1/auth/'):
    return SimpleNamespace(client=SimpleNamespace(host=ip), url=SimpleNamespace(path=path))


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
