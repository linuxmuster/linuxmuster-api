# Source - https://stackoverflow.com/a/76846037
# Posted by SMILE- P, modified by community. See post 'Timeline' for change history
# Retrieved 2026-04-15, License - CC BY-SA 4.0

from fastapi import Request, HTTPException
import time

# In-memory storage for request counters
request_counters = {}

class RateLimiter:
    def __init__(self, requests_limit: int, time_window: int):
        self.requests_limit = requests_limit
        self.time_window = time_window

    async def __call__(self, request: Request):
        client_ip = request.client.host

        # Local callers (e.g. linuxmuster-webui7 running on the same host) are not
        # rate-limited: only requests coming from outside the host are counted.
        if client_ip in {'127.0.0.1', '::1'}:
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
            if current_time - request_counters[key]["timestamp"] > self.time_window:
                # Reset the counter and update the timestamp
                request_counters[key]["timestamp"] = current_time
                request_counters[key]["count"] = 1
            else:
                # Check if the client has exceeded the request limit
                if request_counters[key]["count"] >= self.requests_limit:
                    raise HTTPException(status_code=429, detail="Too Many Requests")
                else:
                    request_counters[key]["count"] += 1

        # Clean up expired client data (optional)
        for k in list(request_counters.keys()):
            if current_time - request_counters[k]["timestamp"] > self.time_window:
                request_counters.pop(k)

        return True