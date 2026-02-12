import pytest
from fastapi.testclient import TestClient

from infraprobe.app import app


@pytest.fixture
def client():
    return TestClient(app)
