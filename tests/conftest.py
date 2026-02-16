import pytest
from fastapi.testclient import TestClient

from infraprobe.app import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
