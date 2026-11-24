import hashlib
import json

import pytest
from conftest import HEADERS, PASSWORD
from fastapi.testclient import TestClient
from sqlalchemy import delete, update

from app import db, demo, vault
from app.main import app

BASE = "/api/v1"


def upload(client, case, data, name="evidence.json", format="json", **fields):
    return client.post(
        case + "/evidence",
        files={"file": (name, data)},
        data={
            "format": format,
            "source": "Orchid synthetic test",
            **fields,
        },
    )


def test_authentication_and_request_guard(open_client):
    assert open_client.get(BASE + "/dashboard").status_code == 401
    payload = {"username": "analyst-test", "password": PASSWORD}
    assert (
        open_client.post(
            BASE + "/auth/login", json={**payload, "password": "wrong"}
        ).status_code
        == 401
    )
    assert (
        open_client.post(
            BASE + "/auth/login",
            json=payload,
            headers={"Origin": "https://untrusted.example"},
        ).status_code
        == 403
    )
    signed = open_client.post(BASE + "/auth/login", json=payload)
    assert signed.status_code == 200
    assert "httponly" in signed.headers["set-cookie"].lower()
    assert "samesite=strict" in signed.headers["set-cookie"].lower()
    assert "password_hash" not in signed.json()
    invalid = open_client.post(
        BASE + "/auth/login", json={**payload, "password": "sensitive" * 40}
    )
    assert invalid.status_code == 422
    assert "sensitive" not in invalid.text
    assert open_client.post(BASE + "/auth/logout").status_code == 204
    assert open_client.get(BASE + "/auth/me").status_code == 401


def test_session_expiry(client):
    token = client.cookies.get("ttx_session")
    from app.security import digest

    with db.transaction() as connection:
        connection.execute(
            update(db.sessions)
            .where(db.sessions.c.id == digest(token))
            .values(expires_at="2000-01-01T00:00:00.000000+00:00")
        )
    assert client.get(BASE + "/auth/me").status_code == 401


def test_case_management_and_isolation(client, case):
    item = upload(client, case, b'{"action":"observed"}').json()
    payload = {
        "title": "Distinct title",
        "investigator": "Analyst",
        "status": "closed",
        "severity": "high",
    }
    assert client.put(case, json=payload).json()["status"] == "closed"
    assert client.get(BASE + "/cases?q=Distinct&severity=high").json()["total"] == 1
    assert client.get(BASE + "/cases?limit=0").status_code == 422
    assert (
        client.put(
            BASE + "/rules/auth_failures",
            json={"enabled": True, "threshold": 5, "window": 10},
        ).status_code
        == 403
    )
    with TestClient(app, headers=HEADERS, base_url="http://127.0.0.1") as outsider:
        assert (
            outsider.post(
                BASE + "/auth/login",
                json={"username": "outside-test", "password": PASSWORD},
            ).status_code
            == 200
        )
        assert outsider.get(case).status_code == 404
        assert outsider.get(case + "/evidence/" + item["id"]).status_code == 404
        assert outsider.post(case + "/reports/json").status_code == 404
        outsider_id = outsider.get(BASE + "/auth/me").json()["id"]
        grant = case + "/access/" + outsider_id
        assert client.put(grant).status_code == 204
        assert outsider.get(case).status_code == 200
        assert client.delete(grant).status_code == 204
        assert outsider.get(case).status_code == 404


def test_upload_security_and_duplicates(client, case):
    payload = b'[{"action":"observed"}]'
    saved = upload(client, case, payload, "../../outside.json")
    assert saved.status_code == 201, saved.text
    item = saved.json()
    assert item["filename"] == "outside.json"
    assert item["sha256"] == hashlib.sha256(payload).hexdigest()
    assert vault.path_for(item["id"]).read_bytes() == payload
    assert upload(client, case, payload).status_code == 409
    assert upload(client, case, b"bad", format="executable").status_code == 422
    assert upload(client, case, b"x" * 1_150_000).status_code == 413
    assert upload(client, case, b"").status_code == 422
    assert (
        client.post(case + "/evidence/" + item["id"] + "/download").content == payload
    )
    with pytest.raises(ValueError):
        vault.path_for("../../outside.json")


def test_malformed_and_clock_correction(client, case):
    payload = b'{"timestamp":"2025-04-08T12:00:00","action":"login"}\ninvalid\n{"action":"gap"}\n'
    response = upload(
        client,
        case,
        payload,
        "sample.jsonl",
        "jsonl",
        timezone_offset=120,
        clock_offset=30,
    )
    assert response.status_code == 201, response.text
    assert response.json()["stats"]["malformed"] == 1
    rows = client.get(case + "/timeline").json()["items"]
    assert rows[0]["timestamp"] == "2025-04-08T10:00:30.000000+00:00"
    assert rows[0]["original_timestamp"] == "2025-04-08T12:00:00"
    assert rows[1]["time_quality"] == "missing"
    assert rows[0]["source_ref"] == "line:1"
    extent = client.get(case + "/timeline/extent").json()
    assert extent["start"] == rows[0]["timestamp"] and extent["undated"] == 1
    trend = client.get(BASE + "/dashboard").json()["trend"]
    assert any(day == "2025-04-08" and count >= 1 for day, count in trend)
    assert client.get(case + "/timeline?start=bad").status_code == 422


def test_integrity_and_custody_tampering(client, case):
    item = upload(client, case, b'{"action":"observed"}').json()
    path = case + "/evidence/" + item["id"]
    assert client.post(path + "/verify").json()["status"] == "verified"
    assert client.get(path + "/custody").json()["verification"]["valid"]
    vault.path_for(item["id"]).write_bytes(b'{"action":"changed!"}')
    assert client.post(path + "/verify").json()["status"] == "failed"
    assert (
        client.post(case + "/analyze", json={"window": 300}).json()[
            "excluded_integrity_failed"
        ]
        == 1
    )
    assert client.get(case + "/findings").json()["items"][0]["rule_id"] == "integrity"
    with db.transaction() as connection:
        connection.execute(
            update(db.custody)
            .where(db.custody.c.evidence_id == item["id"], db.custody.c.sequence == 1)
            .values(reason="altered")
        )
    assert client.get(path + "/custody").json()["verification"]["failed_at"] == 1


def test_missing_tail_is_detected(client, case):
    item = upload(client, case, b'{"action":"tail"}').json()
    path = case + "/evidence/" + item["id"]
    with db.transaction() as connection:
        connection.execute(
            delete(db.custody).where(
                db.custody.c.evidence_id == item["id"],
                db.custody.c.sequence == item["custody_count"],
            )
        )
    assert not client.get(path + "/custody").json()["verification"]["valid"]


def test_complete_investigation_and_exports(client, case):
    primary, secondary, expected = demo.scenario(0)
    evidence = [
        upload(client, case, json.dumps(rows).encode(), f"source-{index}.json").json()
        for index, rows in enumerate((primary, secondary))
    ]
    for item in evidence:
        assert (
            client.post(case + "/evidence/" + item["id"] + "/verify").json()["status"]
            == "verified"
        )
    result = client.post(case + "/analyze", json={"window": 300})
    assert result.status_code == 200, result.text
    assert result.json()["relationships"] > 0
    findings = client.get(case + "/findings").json()["items"]
    assert set(expected) == {item["rule_id"] for item in findings}
    followup = next(item for item in findings if item["rule_id"] == "auth_followup")
    assert len(followup["evidence_ids"]) == 2
    assert followup["confidence"]["components"]["corroboration"]["value"] == 1
    detail = client.get(case + "/events/" + followup["event_ids"][0]).json()
    assert detail["evidence_id"] in followup["evidence_ids"]
    assert followup["id"] in {item["id"] for item in detail["findings"]}
    correlated = client.get(case + "/correlation?kind=finding").json()
    assert correlated["attachments"] and correlated["edges"]
    assert (
        client.post(
            case + "/notes", json={"event_id": detail["id"], "body": "Source reviewed"}
        ).status_code
        == 201
    )
    assert (
        client.patch(
            case + "/findings/" + followup["id"],
            json={
                "stage": "confirmed",
                "reason": "Verified against local change record",
                "override": 90,
            },
        ).status_code
        == 200
    )
    client.post(case + "/analyze", json={"window": 300})
    assert client.get(case + "/findings/" + followup["id"]).json()["override"] == 90
    for format, prefix in (
        ("pdf", b"%PDF"),
        ("html", b"<!doctype"),
        ("json", b"{"),
        ("events.csv", b"\xef\xbb\xbf"),
        ("findings.csv", b"\xef\xbb\xbf"),
    ):
        report = client.post(case + "/reports/" + format)
        assert report.status_code == 200
        assert report.content.startswith(prefix)
    assert client.get(case + "/reports").json()["total"] == 5
    assert (
        client.put(
            case,
            json={"title": "<script>unsafe-title</script>", "investigator": "Analyst"},
        ).status_code
        == 200
    )
    html = client.post(case + "/reports/html")
    assert "<script>" not in html.text
    assert "&lt;script&gt;unsafe-title" in html.text


def test_intelligence_network_and_graph(client, case, tmp_path):
    capture = tmp_path / "capture.pcap"
    demo.pcap(capture)
    assert (
        upload(client, case, capture.read_bytes(), capture.name, "pcap").json()[
            "stats"
        ]["parsed"]
        == 6
    )
    for indicator in (
        {
            "kind": "ipv4",
            "value": "203.0.113.44",
            "source": "Fixture",
            "confidence": 85,
        },
        {
            "kind": "domain",
            "value": "service-0.orchid.example",
            "source": "Fixture",
            "expires_at": "2000-01-01T00:00:00Z",
        },
    ):
        assert client.post(case + "/intelligence", json=indicator).status_code == 201
    assert (
        client.post(
            case + "/intelligence",
            json={"kind": "ipv4", "value": "malformed", "source": "Fixture"},
        ).status_code
        == 422
    )
    assert client.post(case + "/analyze", json={"window": 300}).json()["matches"] == 4
    network = client.get(case + "/network").json()
    assert network["records"] == 6 and network["matches"] == 4 and network["dns"]
    graph = client.get(case + "/correlation?relationship=inferred").json()
    assert graph["nodes"] and graph["edges"]
    scoped = client.get(case + "/correlation?kind=indicator").json()
    assert any(item["kind"] == "indicator" for item in scoped["attachments"])
    edge = graph["edges"][0]
    assert (
        client.patch(
            case + "/correlation/" + edge["id"],
            json={"review": "rejected", "reason": "Test review"},
        ).json()["review"]
        == "rejected"
    )


def test_benign_scenario_review(client, case):
    primary, secondary, _ = demo.scenario(4)
    for index, rows in enumerate((primary, secondary)):
        upload(client, case, json.dumps(rows).encode(), f"test-{index}.json")
    client.post(case + "/analyze", json={"window": 300})
    findings = client.get(case + "/findings").json()["items"]
    assert {row["rule_id"] for row in findings} == {"auth_failures", "auth_followup"}
    assert all(row["stage"] == "suspicious" for row in findings)
    assert (
        client.patch(
            case + "/findings/" + findings[0]["id"],
            json={"stage": "dismissed", "reason": "Authorized maintenance"},
        ).json()["stage"]
        == "dismissed"
    )


def test_case_intake_capacity(client, case, monkeypatch):
    monkeypatch.setattr(vault, "CASE_EVENT_LIMIT", 1)
    assert upload(client, case, b'{"action":"first"}').status_code == 201
    second = upload(client, case, b'{"action":"second"}')
    assert second.status_code == 413
    assert client.get(case + "/evidence").json()["total"] == 1
    assert client.get(case + "/events").json()["total"] == 1
    monkeypatch.setattr(vault, "CASE_BYTES_LIMIT", 1)
    assert upload(client, case, b'{"action":"third"}').status_code == 413


def test_loopback_host_validation(open_client):
    assert (
        open_client.get(BASE + "/health", headers={"Host": "demo.example"}).status_code
        == 400
    )
    assert (
        open_client.get(BASE + "/health", headers={"Host": "localhost"}).status_code
        == 200
    )
