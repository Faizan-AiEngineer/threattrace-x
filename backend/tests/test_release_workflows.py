import csv
import io
import json
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from conftest import HEADERS, PASSWORD
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from test_workflow import upload

from app import db, demo, settings
from app.main import app

BASE = "/api/v1"
TEMPORARY = "synthetic-one-time-7802"
REPLACEMENT = "synthetic-new-local-9403"


def sign_in(client, username, password=PASSWORD):
    return client.post(
        BASE + "/auth/login", json={"username": username, "password": password}
    )


@pytest.fixture
def administrator():
    with TestClient(app, headers=HEADERS, base_url="http://127.0.0.1") as logged_in:
        assert sign_in(logged_in, "admin-test").status_code == 200
        yield logged_in


def csv_events(response):
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    return list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))


def test_export_and_list_share_all_filters_and_case_scope(client, case, administrator):
    match = {
        "action": "training_review",
        "category": "account",
        "severity": "high",
        "hostname": "orchid-host",
        "username": "orchid-user",
    }

    def event(second, **changes):
        return {**match, "timestamp": f"2025-04-08T14:00:{second:02d}Z", **changes}

    rows = [
        event(10),
        event(11),
        event(12, action="unrelated"),
        event(12, category="file"),
        event(12, severity="info"),
        event(12, hostname="different-host"),
        event(12, username="different-user"),
        event(1),
        event(33),
    ]
    evidence = upload(client, case, json.dumps(rows)).json()
    extra = upload(client, case, json.dumps([event(12)]), name="other.json").json()
    other_path = (
        BASE
        + "/cases/"
        + client.post(
            BASE + "/cases",
            json={"title": "Unrelated case", "investigator": "Test"},
        ).json()["id"]
    )
    assert upload(client, other_path, json.dumps([event(13)])).status_code == 201

    filters = {
        "q": "Training",
        "category": "ACCOUNT",
        "severity": "high",
        "host": "ORCHID-HOST",
        "account": "ORCHID-USER",
        "evidence_id": evidence["id"],
        "start": "2025-04-08T14:00:10Z",
        "end": "2025-04-08T14:00:12Z",
    }
    list_url = case + "/timeline"
    export_url = list_url + "/export"
    full = client.get(list_url, params=filters).json()
    assert full["total"] == 2
    filtered = csv_events(
        client.post(export_url, params={**filters, "limit": 1, "page": 2})
    )
    assert [row["id"] for row in filtered] == [row["id"] for row in full["items"]]
    assert {row["evidence_id"] for row in filtered} == {evidence["id"]}
    assert "2 events" in client.get(case + "/activity").json()["items"][0]["detail"]
    assert not any(
        row["action"] == "report_exported"
        for row in client.get(case + "/evidence/" + extra["id"] + "/custody").json()[
            "items"
        ]
    )

    for omit in filters:
        narrowed = {name: value for name, value in filters.items() if name != omit}
        expected = client.get(list_url, params=narrowed).json()
        assert expected["total"] == 3, omit
        assert [
            row["id"] for row in csv_events(client.post(export_url, params=narrowed))
        ] == [row["id"] for row in expected["items"]]
    assert csv_events(client.post(export_url, params={"q": "no matching events"})) == []
    assert client.post(export_url, params={"start": "invalid"}).status_code == 422
    assert (
        len(csv_events(administrator.post(case + "/reports/events.csv")))
        == len(rows) + 1
    )
    with TestClient(app, headers=HEADERS, base_url="http://127.0.0.1") as outsider:
        assert sign_in(outsider, "outside-test").status_code == 200
        assert outsider.post(export_url).status_code == 404


def test_case_grant_visibility_and_idempotent_changes(administrator, client, case):
    created = administrator.post(
        BASE + "/users", json={"username": "grant-target", "password": PASSWORD}
    ).json()
    grants = case + "/access"
    grant = grants + "/" + created["id"]
    assert client.get(grants).json()["owner"]["username"] == "analyst-test"
    assert client.get(grants).json()["items"] == []
    with TestClient(app, headers=HEADERS, base_url="http://127.0.0.1") as grantee:
        assert sign_in(grantee, created["username"]).status_code == 200
        assert grantee.get(case).status_code == 404
        assert client.put(grant).status_code == 204
        assert client.put(grant).status_code == 204
        assert grantee.get(case).status_code == 200
        assert grantee.get(grants).status_code == 403
        assert grantee.delete(grant).status_code == 403
        rows = administrator.get(grants).json()["items"]
        assert len(rows) == 1
        assert rows[0]["user_id"] == created["id"] and rows[0]["created_at"]
        assert not {"password", "password_hash"} & rows[0].keys()
        assert administrator.delete(grant).status_code == 204
        assert administrator.delete(grant).status_code == 204
        assert grantee.get(case).status_code == 404
    audit = administrator.get(BASE + "/users/audit").json()["items"]
    assert [
        row["action"] for row in audit if row["case_id"] == case.rsplit("/", 1)[1]
    ] == [
        "case_access_delete",
        "case_access_put",
    ]
    assert client.get(BASE + "/users/audit").status_code == 403


def test_account_disable_reset_and_forced_change(administrator, client, case):
    created = administrator.post(
        BASE + "/users", json={"username": "lifecycle-target", "password": PASSWORD}
    )
    account = created.json()
    account_url = BASE + "/users/" + account["id"]
    status = {"administrator_password": PASSWORD, "disabled": True}
    reset = {"administrator_password": PASSWORD, "temporary_password": TEMPORARY}
    assert client.patch(account_url + "/status", json=status).status_code == 403
    assert client.post(account_url + "/password", json=reset).status_code == 403
    assert (
        administrator.patch(
            account_url + "/status",
            json={**status, "administrator_password": "incorrect"},
        ).status_code
        == 403
    )
    admin_id = administrator.get(BASE + "/auth/me").json()["id"]
    assert (
        administrator.patch(BASE + f"/users/{admin_id}/status", json=status).status_code
        == 409
    )
    assert (
        administrator.post(BASE + f"/users/{admin_id}/password", json=reset).status_code
        == 409
    )

    with TestClient(app, headers=HEADERS, base_url="http://127.0.0.1") as target:
        assert sign_in(target, account["username"]).status_code == 200
        grant = case + "/access/" + account["id"]
        assert administrator.put(grant).status_code == 204
        assert target.get(case).status_code == 200
        disabled = administrator.patch(account_url + "/status", json=status)
        assert disabled.status_code == 200
        assert disabled.json()["disabled_at"] and "password_hash" not in disabled.json()
        assert target.get(BASE + "/auth/me").status_code == 401
        assert sign_in(target, account["username"]).status_code == 401
        assert (
            administrator.patch(
                account_url + "/status", json={**status, "disabled": False}
            ).status_code
            == 200
        )
        assert target.get(BASE + "/auth/me").status_code == 401
        assert sign_in(target, account["username"]).status_code == 200
        assert target.get(case).status_code == 200
        assert (
            administrator.post(account_url + "/password", json=reset).status_code == 204
        )
        assert target.get(case).status_code == 401
        assert sign_in(target, account["username"]).status_code == 401
        assert sign_in(target, account["username"], TEMPORARY).json()[
            "password_change_required"
        ]
        assert target.get(BASE + "/auth/me").status_code == 200
        assert target.get(case).status_code == 403
        assert target.post(case + "/timeline/export").status_code == 403
        change = {"current_password": TEMPORARY, "new_password": REPLACEMENT}
        assert (
            target.post(
                BASE + "/auth/password", json={**change, "current_password": "wrong"}
            ).status_code
            == 403
        )
        assert target.post(BASE + "/auth/password", json=change).status_code == 204
        assert target.get(BASE + "/auth/me").status_code == 401
        assert sign_in(target, account["username"], TEMPORARY).status_code == 401
        assert not sign_in(target, account["username"], REPLACEMENT).json()[
            "password_change_required"
        ]
        assert target.get(case).status_code == 200

    with db.transaction(write=False) as connection:
        account_audit = list(
            connection.execute(
                select(db.audit).where(
                    (db.audit.c.detail == account["username"])
                    | (db.audit.c.actor == account["username"]),
                )
            ).mappings()
        )
    assert {
        "user_created",
        "user_disabled",
        "user_enabled",
        "user_password_reset",
        "user_password_changed",
    } <= {row["action"] for row in account_audit}
    assert all(
        value not in str(account_audit) for value in (PASSWORD, TEMPORARY, REPLACEMENT)
    )


def test_graph_contains_only_case_provenance(client, case):
    event = {
        "action": "file_access",
        "category": "file",
        "timestamp": "2025-04-08T14:00:10Z",
        "device_id": "orchid-device-14",
        "hostname": "orchid-workstation",
        "username": "training-analyst",
        "source_ip": "192.0.2.14",
        "file_path": "training-report.txt",
    }
    evidence = upload(client, case, json.dumps([event])).json()
    graph = client.get(case + "/correlation?kind=device").json()
    assert graph["sources"] == {evidence["id"]: "evidence.json"}
    assert graph["edges"] == []
    (node,) = graph["nodes"]
    assert node["evidence_id"] == evidence["id"]
    assert {"device", "file", "account", "ip", "host"} == {
        kind for kind, _ in node["entities"]
    }
    assert client.get(case + "/correlation?relationship=inferred").json()["nodes"] == []


def test_openapi_has_tagged_schema_and_required_write_header(open_client):
    schema = open_client.get("/openapi.json").json()
    operations = schema["paths"]
    assert len(schema["tags"]) == 10
    assert all(
        operation.get("tags") and operation.get("description")
        for methods in operations.values()
        for operation in methods.values()
    )
    timeline = operations[BASE + "/cases/{case_id}/timeline/export"]["post"]
    assert {"application/json", "text/csv"} & timeline["responses"]["200"][
        "content"
    ].keys() == {"text/csv"}
    assert any(
        p["name"] == "X-TTX-Request" and p["required"] for p in timeline["parameters"]
    )
    assert {"LocalSession": []} in timeline["security"]
    assert "password_hash" not in schema["components"]["schemas"]["User"]["properties"]


def test_account_metadata_migration_preserves_existing_accounts_and_grants(tmp_path):
    engine = create_engine("sqlite:///" + (tmp_path / "legacy.sqlite3").as_posix())
    config = Config()
    config.set_main_option(
        "script_location", str(Path(db.__file__).resolve().parents[1] / "migrations")
    )
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001")
        connection.execute(
            text(
                "INSERT INTO users (id, username, password_hash, role, created_at) "
                "VALUES ('local-user', 'existing-analyst', 'test-legacy-digest', 'investigator', 'legacy')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO cases (id, title, description, owner_id, investigator, created_at, "
                "updated_at, classification, severity, status, synthetic) VALUES "
                "('existing-case', 'Orchid legacy', '', 'local-user', 'Analyst', 'legacy', "
                "'legacy', 'Synthetic', 'medium', 'open', 1)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO case_access (id, case_id, user_id) "
                "VALUES ('existing-grant', 'existing-case', 'local-user')"
            )
        )
        connection.commit()
        command.upgrade(config, "head")
        account = connection.execute(select(db.users)).mappings().one()
        grant = connection.execute(select(db.grants)).mappings().one()
        assert account["username"] == "existing-analyst"
        assert account["password_hash"] == "test-legacy-digest"
        assert (
            account["disabled_at"] is None
            and account["password_change_required"] is False
        )
        assert grant["user_id"] == account["id"]
        assert grant["case_id"] == "existing-case" and grant["created_at"] is None
    engine.dispose()


def test_demo_cannot_seed_an_existing_investigation_profile(monkeypatch, tmp_path):
    marker = tmp_path / ".synthetic-demo"
    monkeypatch.setattr(settings, "DEMO_PROFILE", marker)
    with pytest.raises(SystemExit, match="separate empty data directory"):
        demo.seed_demo("another-demo-account", PASSWORD, 42)
    assert not marker.exists()


def test_demo_restricts_origins_database_and_remote_clients(monkeypatch, tmp_path):
    marker = tmp_path / ".synthetic-demo"
    marker.touch()
    monkeypatch.setattr(settings, "DEMO_PROFILE", marker)
    with monkeypatch.context() as remote:
        remote.setattr(settings, "ORIGINS", ["https://training.example.invalid"])
        with pytest.raises(ValueError, match="loopback"):
            settings.validate_demo_configuration()
    with monkeypatch.context() as database:
        database.setattr(settings, "DB_URL", "sqlite:///some-other-profile.sqlite3")
        with pytest.raises(ValueError, match="own data directory"):
            settings.validate_demo_configuration()
    with TestClient(
        app, base_url="http://127.0.0.1", client=("192.0.2.42", 50000)
    ) as remote:
        assert remote.get(BASE + "/health").status_code == 403
    with TestClient(
        app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)
    ) as local:
        assert local.get(BASE + "/health").json() == {
            "status": "ok",
            "version": "0.2.0",
        }
