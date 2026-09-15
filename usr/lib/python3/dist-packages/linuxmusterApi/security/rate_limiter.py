# Source - https://stackoverflow.com/a/76846037
# Posted by SMILE- P, modified by community. See post 'Timeline' for change history
# Retrieved 2026-04-15, License - CC BY-SA 4.0

from fastapi import Request, HTTPException
import time

# In-memory storage for request counters
request_counters = {}

# Callers on the host itself (e.g. linuxmuster-webui7) are never counted.
LOOPBACK = {'127.0.0.1', '::1'}


def settings(request):
    """
    Read the rate_limit section of the API configuration.

    Returned as a plain dict so that a missing section, a missing key, or a
    request built outside the app all behave like "use the defaults": the
    dependency guarding the login route must never be the reason a request
    ends in a 500.

    :param request: Incoming request
    :type request: Request
    :rtype: dict
    """

    state = getattr(getattr(request, 'app', None), 'state', None)
    config = getattr(state, 'rate_limit', None)

    return config if isinstance(config, dict) else {}


class RateLimiter:
    def __init__(self, requests_limit: int, time_window: int):
        # Defaults, used until the configuration overrides them.
        self.requests_limit = requests_limit
        self.time_window = time_window

    async def __call__(self, request: Request):
        config = settings(request)
        requests_limit = config.get('requests', self.requests_limit)
        time_window = config.get('window', self.time_window)
        whitelist = config.get('whitelist') or []

        if isinstance(whitelist, str):
            whitelist = [whitelist]

        # Zero or less disables the limiter instead of refusing everything:
        # that is what an admin writing `requests: 0` means.
        if requests_limit <= 0:
            return True

        client_ip = request.client.host

        # A front-end that signs all its users in from one address (edulution)
        # would otherwise spend the whole per-IP budget on the first few of
        # them. See the rate_limit section of config.yml.
        if client_ip in LOOPBACK or client_ip in whitelist:
            return True

        route_path = request.url.path

        # Get the current timestamp
        current_time = int(time.time())

        # Create a unique key based on client IP and route path
        key = f"{client_ip}:{route_path}"

        # Check if client's request counter exists
        if key not in request_counters:
            request_counters[key] = {"timestamp": current_time, "count": 1}
        else:
            # Check if the time window has elapsed, reset the counter if needed
            if current_time - request_counters[key]["timestamp"] > time_window:
                # Reset the counter and update the timestamp
                request_counters[key]["timestamp"] = current_time
                request_counters[key]["count"] = 1
            else:
                # Check if the client has exceeded the request limit
                if request_counters[key]["count"] >= requests_limit:
                    raise HTTPException(status_code=429, detail="Too Many Requests")
                else:
                    request_counters[key]["count"] += 1

        # Clean up expired client data (optional)
        for k in list(request_counters.keys()):
            if current_time - request_counters[k]["timestamp"] > time_window:
                request_counters.pop(k)

        return True