import os
import shutil
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "runtime" / "tests"
TESTS.mkdir(parents=True, exist_ok=True)
DATA = Path(tempfile.mkdtemp(dir=TESTS))
os.environ["TTX_DATA_DIR"] = str(DATA)
os.environ.pop("TTX_DATABASE_URL", None)
os.environ["TTX_MAX_UPLOAD_MIB"] = "1"

from fastapi.testclient import TestClient

from app import db, security
from app.main import app

PASSWORD = "synthetic-local-test-42"
HEADERS = {"X-TTX-Request": "1"}


@pytest.fixture(scope="session", autouse=True)
def database():
    with TestClient(
        app, headers=HEADERS, base_url="http://127.0.0.1"
    ) as initialization:
        assert initialization.get("/api/v1/health").status_code == 200
        with db.transaction() as connection:
            security.create_user(connection, "admin-test", PASSWORD, "administrator")
            security.create_user(connection, "analyst-test", PASSWORD, "investigator")
            security.create_user(connection, "outside-test", PASSWORD, "investigator")
        yield
    db.engine.dispose()
    shutil.rmtree(DATA)


@pytest.fixture
def open_client():
    with TestClient(app, headers=HEADERS, base_url="http://127.0.0.1") as client:
        yield client


@pytest.fixture
def client(open_client):
    response = open_client.post(
        "/api/v1/auth/login", json={"username": "analyst-test", "password": PASSWORD}
    )
    assert response.status_code == 200
    return open_client


@pytest.fixture
def case(client):
    response = client.post(
        "/api/v1/cases",
        json={"title": "Orchid test case", "investigator": "Test investigator"},
    )
    assert response.status_code == 201
    return "/api/v1/cases/" + response.json()["id"]
