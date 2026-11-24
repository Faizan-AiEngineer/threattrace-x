import hashlib
import ipaddress
import itertools
import re
from collections import Counter, defaultdict, deque
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

import networkx as nx
from sqlalchemy import delete, select, update

from . import db, vault
from .settings import CASE_EVENT_LIMIT

VERSION = "1.0"
RULES = {
    "auth_failures": ("Repeated authentication failures", "medium", 5, 300, "T1110"),
    "auth_followup": (
        "Successful authentication after failures",
        "high",
        5,
        300,
        "T1078",
    ),
    "privilege_change": ("Unexpected privilege change", "high", 1, 300, "T1098"),
    "admin_activity": ("Unusual administrative activity", "medium", 1, 300, None),
    "process_start": ("Flagged process execution", "high", 1, 300, None),
    "service_change": (
        "Unexpected service configuration change",
        "medium",
        1,
        300,
        None,
    ),
    "network_unusual": ("Unusual network activity", "medium", 1, 300, None),
    "transfer": ("Large network transfer", "high", 1_000_000, 300, None),
    "file_access": ("Flagged file access", "high", 1, 300, None),
    "indicator": ("Exact indicator match", "high", 1, 300, None),
    "integrity": ("Evidence integrity failure", "critical", 1, 300, None),
}
WEIGHTS = {
    "integrity": 0.25,
    "corroboration": 0.2,
    "timestamps": 0.15,
    "indicators": 0.1,
    "correlation": 0.15,
    "completeness": 0.15,
}
ATTRIBUTES = {
    "username": "account",
    "hostname": "host",
    "source_ip": "ip",
    "destination_ip": "ip",
    "process_name": "process",
    "file_path": "file",
    "file_hash": "hash",
    "domain": "domain",
    "url": "url",
}


def key_for(*items):
    return hashlib.sha256("\0".join(items).encode()).hexdigest()


def items(connection, table, case_id, *predicates):
    return [
        dict(row)
        for row in connection.execute(
            select(table).where(table.c.case_id == case_id, *predicates)
        ).mappings()
    ]


def rule_config(connection):
    stored = {
        row["id"]: dict(row) for row in connection.execute(select(db.rules)).mappings()
    }
    return [
        {
            "id": key,
            "name": name,
            "severity": severity,
            "technique": technique,
            "version": VERSION,
            "enabled": data.get("enabled", True),
            "threshold": data.get("threshold", threshold),
            "window": data.get("window", window),
        }
        for key, (name, severity, threshold, window, technique) in RULES.items()
        for data in [stored.get(key, {})]
    ]


def entity_keys(event):
    pairs = {(kind, event[field]) for field, kind in ATTRIBUTES.items() if event[field]}
    if event["hostname"] and event["process_id"]:
        pairs.add(("process_id", f"{event['hostname']}/{event['process_id']}"))
    return pairs


def event_order(event):
    return event["timestamp"] is None, event["timestamp"] or "", event["id"]


def correlate(events, window, matched=None):
    recent = defaultdict(lambda: deque(maxlen=6))
    graph = nx.DiGraph()
    matched = matched or {}
    for event in sorted(events, key=event_order):
        if not event["timestamp"]:
            continue
        now = datetime.fromisoformat(event["timestamp"]).timestamp()
        keys = entity_keys(event) | {("evidence", event["evidence_id"])}
        keys |= {("indicator", item["id"]) for item in matched.get(event["id"], [])}
        links = defaultdict(list)
        for attribute in sorted(keys):
            for moment, earlier in reversed(recent[attribute]):
                if now - moment <= window:
                    links[earlier].append(
                        {
                            "kind": attribute[0],
                            "value": attribute[1],
                            "seconds_apart": round(now - moment, 6),
                        }
                    )
        ranked = sorted(
            links.items(),
            key=lambda pair: (
                -sum(a["kind"] != "evidence" for a in pair[1]),
                pair[1][0]["seconds_apart"],
                pair[0],
            ),
        )
        for earlier, attributes in ranked[:4]:
            count = sum(a["kind"] != "evidence" for a in attributes)
            observed = not count
            graph.add_edge(
                earlier,
                event["id"],
                kind="observed" if observed else "inferred",
                attributes=attributes,
                confidence=round(min(0.95, 0.4 + count * 0.15), 2),
                explanation="Same evidence item within the configured window"
                if observed
                else "Shared contextual attributes within the configured window",
                version=VERSION,
            )
        for attribute in keys:
            recent[attribute].append((now, event["id"]))
    return graph


def canonical_indicator(kind, value):
    value = str(value).strip()
    if kind in {"ipv4", "ipv6", "ip"}:
        addr = ipaddress.ip_address(value)
        if kind != "ip" and kind != f"ipv{addr.version}":
            raise ValueError("IP version mismatch")
        return f"ipv{addr.version}", str(addr)
    if kind == "domain":
        value = value.rstrip(".").encode("idna").decode().lower()
        if (
            len(value) <= 253
            and "." in value
            and all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in value.split(".")
            )
        ):
            return kind, value
    lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
    if (
        kind in lengths
        and len(value) == lengths[kind]
        and re.fullmatch("[0-9a-fA-F]+", value)
    ):
        return kind, value.lower()
    if kind == "url":
        parsed = urlsplit(value)
        if (
            parsed.scheme in {"http", "https"}
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not any(char.isspace() for char in value)
        ):
            return kind, urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc.lower(),
                    parsed.path or "/",
                    parsed.query,
                    "",
                )
            )
    raise ValueError(f"Invalid {kind} indicator")


def indicator_matches(events, indicators):
    index = {
        (row["kind"], row["value"]): row
        for row in indicators
        if not row["expires_at"] or row["expires_at"] > db.utc()
    }
    found = {}
    for event in events:
        fields = {
            "source_ip": "ip",
            "destination_ip": "ip",
            "domain": "domain",
            "url": "url",
            "file_hash": {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(
                len(event["file_hash"] or ""), ""
            ),
        }
        hits = {}
        for field, kind in fields.items():
            if event[field] and kind:
                try:
                    row = index.get(canonical_indicator(kind, event[field]))
                    if row:
                        hits[row["id"]] = row
                except ValueError:
                    continue
        if hits:
            found[event["id"]] = list(hits.values())
    return found


def score(support, evidence, indicator_rows=(), consistency=None):
    sources = {row["evidence_id"] for row in support}
    if not evidence:
        return {"score": None, "category": "insufficient", "components": {}}
    availability = {"verified": 1, "unverified": 0.5, "failed": 0}
    time_quality = {"explicit": 1, "assumed": 0.5, "uncertain": 0, "missing": 0}
    values = {
        "integrity": sum(availability[row["integrity"]] for row in evidence)
        / len(evidence),
        "corroboration": min(1, len(sources) / 2) if support else None,
        "timestamps": sum(time_quality[row["time_quality"]] for row in support)
        / len(support)
        if support
        else None,
        "indicators": max(row["confidence"] for row in indicator_rows) / 100
        if indicator_rows
        else None,
        "correlation": consistency,
        "completeness": sum(
            1
            if row["state"] == "processed"
            else 0.5
            if row["state"] == "partial"
            else 0
            for row in evidence
        )
        / len(evidence),
    }
    components = {
        name: {
            "weight": WEIGHTS[name],
            "value": val,
            "contribution": round(WEIGHTS[name] * val, 4) if val is not None else None,
        }
        for name, val in values.items()
    }
    total = sum(WEIGHTS[name] for name, val in values.items() if val is not None)
    result = round(
        100
        * sum(WEIGHTS[name] * val for name, val in values.items() if val is not None)
        / total
    )
    return {
        "score": result,
        "category": "high" if result >= 75 else "moderate" if result >= 45 else "low",
        "components": components,
    }


def predictions(events, evidence, matched, configs):
    config = {rule["id"]: rule for rule in configs if rule["enabled"]}
    failures = defaultdict(deque)
    flags = {
        "privilege_change",
        "admin_activity",
        "process_start",
        "service_change",
        "file_access",
    }
    auth = {
        key: config[key] for key in ("auth_failures", "auth_followup") if key in config
    }
    for event in sorted(events, key=event_order):
        if (
            auth
            and event["category"] == "authentication"
            and event["username"]
            and event["timestamp"]
        ):
            identity = (
                event["username"],
                event["hostname"] or event["destination_ip"] or event["source_ip"],
            )
            if identity[1]:
                now = datetime.fromisoformat(event["timestamp"]).timestamp()
                for rule_id, rule in auth.items():
                    history = failures[(rule_id, identity)]
                    while history and now - history[0][0] > rule["window"]:
                        history.popleft()
                    if event["outcome"] == "failure":
                        history.append((now, event))
                        if (
                            len(history) == rule["threshold"]
                            and rule_id == "auth_failures"
                        ):
                            yield (
                                rule_id,
                                [row for _, row in history],
                                [],
                                [],
                                f"{len(history)} failures in {rule['window']} seconds for {identity[0]}.",
                            )
                    elif event["outcome"] == "success":
                        if (
                            len(history) >= rule["threshold"]
                            and rule_id == "auth_followup"
                        ):
                            yield (
                                rule_id,
                                [row for _, row in list(history)[-rule["threshold"] :]]
                                + [event],
                                [],
                                [],
                                "Successful sign-in followed repeated failures for the same account and destination context.",
                            )
                        history.clear()
        rule_id = event["action"]
        metadata = event["metadata"]
        expected = str(metadata.get("expected", "")).lower() in {"true", "1", "yes"}
        flagged = str(metadata.get("flagged", "")).lower() in {"true", "1", "yes"}
        if (
            rule_id in flags & config.keys()
            and not expected
            and (flagged or rule_id in {"privilege_change", "service_change"})
        ):
            yield (
                rule_id,
                [event],
                [],
                [],
                f"Source record describes {rule_id.replace('_', ' ')} without an expected-change marker.",
            )
        if event["category"] == "network":
            if (
                "transfer" in config
                and (event["bytes"] or 0) >= config["transfer"]["threshold"]
            ):
                yield (
                    "transfer",
                    [event],
                    [],
                    [],
                    f"Record reports {event['bytes']:,} bytes, meeting the configured threshold.",
                )
            if "network_unusual" in config and flagged and not expected:
                yield (
                    "network_unusual",
                    [event],
                    [],
                    [],
                    "Source marked this network observation as unusual.",
                )
        if "indicator" in config and event["id"] in matched:
            yield (
                "indicator",
                [event],
                [],
                matched[event["id"]],
                "An event attribute exactly matches an unexpired local indicator.",
            )
    if "integrity" in config:
        for row in evidence:
            if row["integrity"] == "failed":
                yield (
                    "integrity",
                    [],
                    [row["id"]],
                    [],
                    "The preserved bytes failed verification against the original SHA-256.",
                )


def bulk(connection, table, rows):
    for start in range(0, len(rows), 1000):
        connection.execute(table.insert(), rows[start : start + 1000])


def analyze(connection, case_id, actor, window):
    evidence = items(connection, db.evidence, case_id)
    event_rows = [
        dict(row)
        for row in connection.execute(
            select(db.events)
            .where(db.events.c.case_id == case_id)
            .order_by(
                db.events.c.timestamp.is_(None), db.events.c.timestamp, db.events.c.id
            )
            .limit(CASE_EVENT_LIMIT + 1)
        ).mappings()
    ]
    if len(event_rows) > CASE_EVENT_LIMIT:
        from fastapi import HTTPException

        raise HTTPException(
            422, f"Case analysis supports up to {CASE_EVENT_LIMIT:,} events"
        )
    safe = {row["id"]: row for row in evidence if row["integrity"] != "failed"}
    events = [row for row in event_rows if row["evidence_id"] in safe]
    matched = indicator_matches(events, items(connection, db.indicators, case_id))
    graph = correlate(events, window, matched)
    configs = {row["id"]: row for row in rule_config(connection)}
    connection.execute(delete(db.matches).where(db.matches.c.case_id == case_id))
    bulk(
        connection,
        db.matches,
        [
            {
                "id": key_for(row["id"], event_id),
                "case_id": case_id,
                "indicator_id": row["id"],
                "event_id": event_id,
            }
            for event_id, hits in matched.items()
            for row in hits
        ],
    )
    connection.execute(delete(db.entities).where(db.entities.c.case_id == case_id))
    entity_rows, links = {}, []
    for event in events:
        for kind, value in sorted(entity_keys(event)):
            entity_id = key_for(case_id, kind, value)
            entity_rows[entity_id] = {
                "id": entity_id,
                "case_id": case_id,
                "kind": kind,
                "value": value,
            }
            links.append(
                {
                    "id": key_for(entity_id, event["id"]),
                    "entity_id": entity_id,
                    "event_id": event["id"],
                }
            )
    bulk(connection, db.entities, list(entity_rows.values()))
    bulk(connection, db.entity_events, links)
    old_edges = {row["id"]: row for row in items(connection, db.relationships, case_id)}
    connection.execute(
        update(db.relationships)
        .where(db.relationships.c.case_id == case_id)
        .values(active=False)
    )
    new_edges = []
    for left, right, attrs in graph.edges(data=True):
        edge_id = key_for(case_id, left, right)
        values = dict(
            case_id=case_id, source_id=left, target_id=right, active=True, **attrs
        )
        if edge_id in old_edges:
            connection.execute(
                update(db.relationships)
                .where(db.relationships.c.id == edge_id)
                .values(**values)
            )
        else:
            new_edges.append(dict(id=edge_id, review="pending", reason="", **values))
    bulk(connection, db.relationships, new_edges)
    old_findings = {row["id"]: row for row in items(connection, db.findings, case_id)}
    connection.execute(
        update(db.findings).where(db.findings.c.case_id == case_id).values(active=False)
    )
    count = 0
    for rule_id, support, evidence_ids, indicators, explanation in predictions(
        events, evidence, matched, configs.values()
    ):
        rule = configs[rule_id]
        evidence_ids = sorted(
            set(evidence_ids) | {row["evidence_id"] for row in support}
        )
        event_ids = [row["id"] for row in support]
        finding_id = key_for(case_id, rule_id, *sorted(event_ids), *evidence_ids)
        consistency = None
        if len(event_ids) > 1:
            consistency = sum(
                graph.has_edge(left, right)
                for left, right in itertools.pairwise(event_ids)
            ) / (len(event_ids) - 1)
        confidence = score(
            support,
            [row for row in evidence if row["id"] in evidence_ids],
            indicators,
            consistency,
        )
        values = {
            "case_id": case_id,
            "rule_id": rule_id,
            "version": VERSION,
            "name": rule["name"],
            "severity": rule["severity"],
            "explanation": explanation,
            "steps": "Review the linked records and compare against independent logs and change records.",
            "limitations": "Source context may be incomplete. Rule and indicator associations require investigation.",
            "technique": rule["technique"],
            "confidence": confidence,
            "active": True,
            "timestamp": support[-1]["timestamp"] if support else None,
        }
        if finding_id in old_findings:
            connection.execute(
                update(db.findings)
                .where(db.findings.c.id == finding_id)
                .values(**values)
            )
        else:
            db.add(
                connection,
                db.findings,
                id=finding_id,
                stage="observation"
                if rule_id in {"integrity", "indicator"}
                else "suspicious",
                review_reason="",
                override=None,
                **values,
            )
            bulk(
                connection,
                db.finding_events,
                [
                    {
                        "id": key_for(finding_id, event_id),
                        "finding_id": finding_id,
                        "event_id": event_id,
                    }
                    for event_id in event_ids
                ],
            )
            bulk(
                connection,
                db.finding_evidence,
                [
                    {
                        "id": key_for(finding_id, evidence_id),
                        "finding_id": finding_id,
                        "evidence_id": evidence_id,
                    }
                    for evidence_id in evidence_ids
                ],
            )
        count += 1
    for row in evidence:
        vault.custody_append(
            connection,
            row["id"],
            actor,
            "analysis_executed",
            f"Correlation window {window}s",
        )
    db.record(
        connection,
        actor,
        "analysis_executed",
        case_id,
        f"{count} findings, {graph.number_of_edges()} relationships",
    )
    return {
        "events": len(events),
        "excluded_integrity_failed": len(event_rows) - len(events),
        "findings": count,
        "relationships": graph.number_of_edges(),
        "matches": sum(map(len, matched.values())),
    }


def enrich_finding(connection, row):
    result = dict(row)
    for table, field in (
        (db.finding_events, "event_id"),
        (db.finding_evidence, "evidence_id"),
    ):
        result[field + "s"] = list(
            connection.scalars(
                select(table.c[field]).where(table.c.finding_id == row["id"])
            )
        )
    return result


def network(rows):
    protocols, sources, destinations, ports, dns, flows = (Counter() for _ in range(6))
    byte_total = records = 0
    for records, row in enumerate(rows, 1):
        protocols[row["protocol"] or "unknown"] += 1
        if row["source_ip"]:
            sources[row["source_ip"]] += 1
        if row["destination_ip"]:
            destinations[row["destination_ip"]] += 1
        if row["destination_port"] is not None:
            ports[str(row["destination_port"])] += 1
        if row["domain"]:
            dns[row["domain"]] += 1
        if row["source_ip"] and row["destination_ip"]:
            flows[
                (
                    row["source_ip"],
                    row["destination_ip"],
                    row["protocol"] or "unknown",
                    row["source_port"],
                    row["destination_port"],
                )
            ] += 1
        byte_total += row["bytes"] or 0
    return {
        "records": records,
        "bytes": byte_total,
        "protocols": protocols.most_common(20),
        "sources": sources.most_common(20),
        "destinations": destinations.most_common(20),
        "ports": ports.most_common(20),
        "dns": dns.most_common(20),
        "flows": [
            {
                "source": a,
                "destination": b,
                "protocol": protocol,
                "source_port": sp,
                "destination_port": dp,
                "records": count,
            }
            for (a, b, protocol, sp, dp), count in flows.most_common(100)
        ],
    }
