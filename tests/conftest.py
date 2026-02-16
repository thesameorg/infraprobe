import pytest
from fastapi.testclient import TestClient

from infraprobe.app import app


def pytest_addoption(parser):
    parser.addoption("--no-integration", action="store_true", default=False, help="Skip integration tests")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--no-integration"):
        skip = pytest.mark.skip(reason="Integration tests skipped (--no-integration)")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
