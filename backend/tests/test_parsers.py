import pytest

from app import analysis, parsers, reporting


@pytest.mark.parametrize(
    ("format", "text", "action"),
    [
        ("json", '{"action":"observed"}', "observed"),
        ("jsonl", '{"action":"observed"}\n', "observed"),
        ("csv", "timestamp,action\n2025-04-08T09:00:00Z,observed\n", "observed"),
        ("syslog", "2025-04-08T09:00:00Z orchid sample message\n", "syslog"),
        (
            "auth",
            "2025-04-08T09:00:00Z orchid sshd: Failed password for analyst from 192.0.2.20 port 52222\n",
            "login",
        ),
        (
            "access",
            '192.0.2.20 - - [08/Apr/2025:09:00:00 +0000] "GET / HTTP/1.1" 200 275\n',
            "get",
        ),
        (
            "zeek",
            "#separator \\x09\n#fields\tts\tid.orig_h\n1744102800\t192.0.2.20\n",
            "observed",
        ),
        (
            "windows",
            '{"EventID":4625,"TimeCreated":"2025-04-08T09:00:00Z","Computer":"Orchid"}',
            "login",
        ),
    ],
)
def test_supported_formats(tmp_path, format, text, action):
    path = tmp_path / "evidence"
    path.write_text(text, encoding="utf-8")
    result = parsers.parse(path, format)
    assert result.stats["parsed"] == 1
    assert result.events[0]["action"] == action
    assert result.events[0]["source_ref"]


def test_csv_and_html_output_safety():
    assert reporting.safe_csv("=1+1") == "'=1+1"
    assert reporting.safe_csv("   @SUM") == "'   @SUM"


def test_confidence_handles_missing_inputs():
    assert analysis.score([], [])["category"] == "insufficient"
    common = {"state": "processed"}
    assert (
        analysis.score([], [{**common, "integrity": "verified"}])["score"]
        > analysis.score([], [{**common, "integrity": "failed"}])["score"]
    )


def test_invalid_json_records_remain_skippable(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_bytes(
        b'{"action":"observed","measurement":1e309}\n'
        b'{"action":"observed","hostname":"\\ud800"}\n'
        b'{"action":"observed","measurement":1.25}\n'
    )
    result = parsers.parse(path, "jsonl")
    assert result.stats["malformed"] == 2
    assert result.events[0]["source_ref"] == "line:3"
