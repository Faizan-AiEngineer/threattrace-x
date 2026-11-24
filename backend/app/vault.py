import hashlib
import json
import os
import re
from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import HTTPException
from sqlalchemy import func, select, update

from . import db, parsers
from .settings import (
    CASE_BYTES_LIMIT,
    CASE_EVENT_LIMIT,
    CASE_EVIDENCE_LIMIT,
    MAX_BYTES,
    VAULT,
)

CHUNK = 256 * 1024


def hash_stream(stream, target=None, max_bytes=None):
    digest = hashlib.sha256()
    size = 0
    while data := stream.read(CHUNK):
        size += len(data)
        if max_bytes is not None and size > max_bytes:
            raise HTTPException(413, "Evidence exceeds the configured upload limit")
        digest.update(data)
        if target:
            target.write(data)
    return digest.hexdigest(), size


def path_for(evidence_id):
    if not re.fullmatch(r"[0-9a-f-]{36}", evidence_id):
        raise ValueError("Invalid evidence storage identifier")
    return VAULT / (evidence_id + ".bin")


def canonical_hash(row):
    keys = (
        "id",
        "evidence_id",
        "sequence",
        "actor",
        "action",
        "timestamp",
        "reason",
        "previous_hash",
    )
    payload = json.dumps(
        {key: row[key] for key in keys},
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def custody_append(connection, evidence_id, actor, action, reason):
    item = db.one(connection, db.evidence, db.evidence.c.id == evidence_id)
    record = {
        "id": db.uid(),
        "evidence_id": evidence_id,
        "sequence": item["custody_count"] + 1,
        "actor": actor,
        "action": action,
        "timestamp": db.utc(),
        "reason": reason,
        "previous_hash": item["custody_head"],
    }
    record["record_hash"] = canonical_hash(record)
    db.add(connection, db.custody, **record)
    connection.execute(
        update(db.evidence)
        .where(db.evidence.c.id == evidence_id)
        .values(custody_head=record["record_hash"], custody_count=record["sequence"])
    )
    return record


def custody_verify(connection, item):
    selector = db.custody.c.evidence_id == item["id"]
    rows = connection.execute(
        select(db.custody).where(selector).order_by(db.custody.c.sequence)
    ).mappings()
    previous = None
    count = 0
    for count, row in enumerate(rows, 1):
        if (
            row["sequence"] != count
            or row["previous_hash"] != previous
            or canonical_hash(row) != row["record_hash"]
        ):
            return {
                "valid": False,
                "records": connection.scalar(
                    select(func.count()).select_from(db.custody).where(selector)
                ),
                "failed_at": count,
                "reason": "Record or link mismatch",
            }
        previous = row["record_hash"]
    valid = count == item["custody_count"] and previous == item["custody_head"]
    return {
        "valid": valid,
        "records": count,
        "failed_at": None,
        "reason": None if valid else "Recorded head or count mismatch",
    }


def import_file(
    case_id,
    actor,
    stream,
    original_name,
    format,
    source,
    collection_at,
    timezone_offset,
    clock_offset,
    *,
    user=None,
):
    if format not in parsers.FORMATS:
        raise HTTPException(422, "Unsupported evidence format")
    filename = re.split(r"[/\\]", original_name or "")[-1]
    filename = "".join(char for char in filename if char.isprintable())[:255]
    if not filename or filename in {".", ".."}:
        raise HTTPException(422, "Evidence requires a filename")
    if collection_at:
        _, collection_at, quality = parsers.timestamp(collection_at, timezone_offset)
        if quality == "uncertain":
            raise HTTPException(422, "Invalid collection timestamp")
    evidence_id = db.uid()
    destination = path_for(evidence_id)
    staged = None
    moved = False
    try:
        with NamedTemporaryFile(dir=VAULT, prefix="intake-", delete=False) as target:
            staged = Path(target.name)
            digest, size = hash_stream(stream, target, MAX_BYTES)
            target.flush()
            os.fsync(target.fileno())
        if not size:
            raise HTTPException(422, "Empty evidence file")
        with db.transaction(write=False) as connection:
            reject_duplicate(connection, case_id, digest)
            enforce_case_capacity(connection, case_id, size)
        result = parsers.parse(staged, format, timezone_offset, clock_offset)
        with db.transaction() as connection:
            if user:
                from .security import require_case

                require_case(connection, user, case_id)
            reject_duplicate(connection, case_id, digest)
            enforce_case_capacity(connection, case_id, size, len(result.events))
            os.replace(staged, destination)
            moved = True
            item = db.add(
                connection,
                db.evidence,
                id=evidence_id,
                case_id=case_id,
                filename=filename,
                size=size,
                format=format,
                sha256=digest,
                collection_at=collection_at,
                imported_at=db.utc(),
                source=source,
                uploader=actor,
                custodian=actor,
                integrity="unverified",
                parser_version=parsers.VERSION,
                state="failed"
                if result.stats["failed"]
                else (
                    "partial"
                    if result.stats["malformed"] or result.stats["truncated"]
                    else "processed"
                ),
                stats=result.stats,
                clock_offset=clock_offset,
                timezone_offset=timezone_offset,
                custody_count=0,
                custody_head=None,
            )
            if collection_at:
                custody_append(
                    connection,
                    evidence_id,
                    actor,
                    "collection_registered",
                    f"{collection_at} · {source}",
                )
            custody_append(
                connection, evidence_id, actor, "imported", f"Preserved {size} bytes"
            )
            custody_append(
                connection,
                evidence_id,
                actor,
                "parsed",
                f"{result.stats['parsed']} normalized records",
            )
            for start in range(0, len(result.events), 1000):
                connection.execute(
                    db.events.insert(),
                    [
                        dict(
                            event, case_id=case_id, evidence_id=evidence_id, id=db.uid()
                        )
                        for event in result.events[start : start + 1000]
                    ],
                )
            db.record(connection, actor, "evidence_imported", case_id, evidence_id)
            item = db.one(connection, db.evidence, db.evidence.c.id == evidence_id)
        return item
    except BaseException:
        if moved:
            destination.unlink(missing_ok=True)
        raise
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def enforce_case_capacity(connection, case_id, size, events=0):
    count, total_bytes = connection.execute(
        select(func.count(), func.coalesce(func.sum(db.evidence.c.size), 0)).where(
            db.evidence.c.case_id == case_id
        )
    ).one()
    if count >= CASE_EVIDENCE_LIMIT or total_bytes + size > CASE_BYTES_LIMIT:
        raise HTTPException(
            413, "This investigation has reached its evidence storage limit"
        )
    if events:
        total_events = connection.scalar(
            select(func.count())
            .select_from(db.events)
            .where(db.events.c.case_id == case_id)
        )
        if total_events + events > CASE_EVENT_LIMIT:
            raise HTTPException(
                413, "This investigation has reached its normalized event limit"
            )


def reject_duplicate(connection, case_id, digest):
    duplicate = db.one(
        connection,
        db.evidence,
        db.evidence.c.case_id == case_id,
        db.evidence.c.sha256 == digest,
    )
    if duplicate:
        raise HTTPException(
            409, f"Identical evidence already exists in this case ({duplicate['id']})"
        )


def verify(connection, item, actor):
    try:
        with path_for(item["id"]).open("rb") as stream:
            actual, size = hash_stream(stream, max_bytes=item["size"])
            status = (
                "verified"
                if (actual, size) == (item["sha256"], item["size"])
                else "failed"
            )
    except (OSError, HTTPException):
        actual, status = None, "failed"
    db.add(
        connection,
        db.verifications,
        evidence_id=item["id"],
        actor=actor,
        timestamp=db.utc(),
        actual_hash=actual,
        status=status,
    )
    connection.execute(
        update(db.evidence)
        .where(db.evidence.c.id == item["id"])
        .values(integrity=status)
    )
    custody_append(connection, item["id"], actor, "integrity_verified", status)
    db.record(connection, actor, "integrity_" + status, item["case_id"], item["id"])
    return {"status": status, "expected_hash": item["sha256"], "actual_hash": actual}
