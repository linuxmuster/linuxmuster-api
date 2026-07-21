import sys
import pytest
from fastapi.testclient import TestClient

from . import credentials
from .credentials import LOCAL_API_PATH

# Inject fallback values for test-data variables not yet set in credentials.py.
# Tests relying on these will fail with 404 until the real values are configured.
_TEST_DATA_DEFAULTS = {
    'SCHOOL': 'default-school',
    'SCHOOLCLASS': 'UNCONFIGURED',
    'EXTRACLASS': 'UNCONFIGURED',
    'PROJECT': 'UNCONFIGURED',
    'PRINTER': 'UNCONFIGURED',
    'MGMT_GROUP': 'UNCONFIGURED',
    'GROUP': 'UNCONFIGURED',
    'DEVICE': 'UNCONFIGURED',
}
for _var, _default in _TEST_DATA_DEFAULTS.items():
    if not hasattr(credentials, _var):
        setattr(credentials, _var, _default)

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
