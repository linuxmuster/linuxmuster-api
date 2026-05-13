import sys
import pytest
from fastapi.testclient import TestClient

from .credentials import LOCAL_API_PATH

sys.path.append(LOCAL_API_PATH)
from main import app
from security.rate_limiter import request_counters


@pytest.fixture(scope="session", autouse=True)
def lifespan():
    with TestClient(app):
        yield

@pytest.fixture(autouse=True)
def reset_rate_limiter():
    request_counters.clear()
