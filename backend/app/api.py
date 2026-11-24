import csv
import io
import json
from collections import Counter
from typing import Annotated, Literal

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from starlette.responses import FileResponse

from . import analysis, db, parsers, reporting, schemas, security, settings, vault

router = APIRouter(prefix="/api/v1")
User = Annotated[dict, Depends(security.current)]
Page = Annotated[int, Query(ge=1, le=100_000)]
Limit = Annotated[int, Query(ge=1, le=200)]
Search = Annotated[str, Query(max_length=200)]


def page_of(connection, query, page, limit):
    count = connection.scalar(
        select(func.count()).select_from(query.order_by(None).subquery())
    )
    rows = connection.execute(query.offset((page - 1) * limit).limit(limit)).mappings()
    return {
        "items": [dict(row) for row in rows],
        "total": count,
        "page": page,
        "limit": limit,
    }


def public_user(user):
    return {key: user[key] for key in ("id", "username", "role", "created_at")}


def case_row(connection, table, case_id, item_id):
    item = db.one(connection, table, table.c.id == item_id, table.c.case_id == case_id)
    if not item:
        raise HTTPException(404, "Case item not found")
    return item


def edit(connection, table, item_id, **values):
    connection.execute(update(table).where(table.c.id == item_id).values(**values))
    return db.one(connection, table, table.c.id == item_id)


@router.get("/health")
def health():
    with db.transaction(write=False) as connection:
        connection.execute(select(1))
    return {"status": "ok", "version": "0.1.0"}


@router.post("/auth/login")
def login(payload: schemas.Login, response: Response):
    user, token = security.login(payload.username, payload.password)
    response.set_cookie(
        security.COOKIE,
        token,
        max_age=settings.SESSION_HOURS * 3600,
        httponly=True,
        samesite="strict",
        secure=settings.SECURE_COOKIE,
    )
    return public_user(user)


@router.get("/auth/me")
def me(user: User):
    return public_user(user)


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response, user: User):
    with db.transaction() as connection:
        connection.execute(
            delete(db.sessions).where(
                db.sessions.c.id == security.digest(request.cookies[security.COOKIE])
            )
        )
        db.record(connection, user["username"], "signed_out")
    response.delete_cookie(security.COOKIE)


@router.get("/users")
def users(user: User):
    security.admin(user)
    with db.transaction(write=False) as connection:
        return [
            public_user(row)
            for row in connection.execute(
                select(db.users).order_by(db.users.c.username)
            ).mappings()
        ]


@router.post("/users", status_code=201)
def create_user(payload: schemas.UserCreate, user: User):
    security.admin(user)
    try:
        with db.transaction() as connection:
            created = security.create_user(
                connection, payload.username, payload.password, payload.role
            )
            db.record(
                connection, user["username"], "user_created", detail=created["username"]
            )
            return public_user(created)
    except IntegrityError as error:
        raise HTTPException(409, "Username already exists") from error


@router.get("/cases")
def cases(
    user: User,
    page: Page = 1,
    limit: Limit = 30,
    q: Search = "",
    status: schemas.Status | None = None,
    severity: schemas.Severity | None = None,
    sort: Literal["recent", "oldest", "title"] = "recent",
):
    query = select(db.cases).where(security.scope(user))
    if q:
        query = query.where(
            or_(
                db.cases.c.title.icontains(q, autoescape=True),
                db.cases.c.description.icontains(q, autoescape=True),
            )
        )
    if status:
        query = query.where(db.cases.c.status == status)
    if severity:
        query = query.where(db.cases.c.severity == severity)
    order = {
        "recent": db.cases.c.updated_at.desc(),
        "oldest": db.cases.c.created_at,
        "title": db.cases.c.title,
    }
    with db.transaction(write=False) as connection:
        return page_of(
            connection, query.order_by(order[sort], db.cases.c.id), page, limit
        )


@router.post("/cases", status_code=201)
def create_case(payload: schemas.CaseInput, user: User):
    with db.transaction() as connection:
        case = db.add(
            connection,
            db.cases,
            owner_id=user["id"],
            created_at=db.utc(),
            updated_at=db.utc(),
            synthetic=False,
            **payload.model_dump(),
        )
        db.record(connection, user["username"], "case_created", case["id"])
        return case


@router.get("/cases/{case_id}")
def get_case(case_id: str, user: User):
    with db.transaction(write=False) as connection:
        return security.require_case(connection, user, case_id)


@router.put("/cases/{case_id}")
def update_case(case_id: str, payload: schemas.CaseInput, user: User):
    with db.transaction() as connection:
        case = security.require_case(connection, user, case_id)
        result = edit(
            connection, db.cases, case_id, updated_at=db.utc(), **payload.model_dump()
        )
        if case["status"] != "archived" and payload.status == "archived":
            for item in analysis.items(connection, db.evidence, case_id):
                vault.custody_append(
                    connection,
                    item["id"],
                    user["username"],
                    "archived",
                    "Case status archived",
                )
        db.record(connection, user["username"], "case_updated", case_id, payload.status)
        return result


@router.put("/cases/{case_id}/access/{user_id}", status_code=204)
@router.delete("/cases/{case_id}/access/{user_id}", status_code=204)
def case_access(case_id: str, user_id: str, user: User, request: Request):
    with db.transaction() as connection:
        case = security.require_case(connection, user, case_id)
        if user["id"] != case["owner_id"]:
            security.admin(user)
        recipient = db.one(connection, db.users, db.users.c.id == user_id)
        if not recipient:
            raise HTTPException(404, "User not found")
        match = (db.grants.c.case_id == case_id, db.grants.c.user_id == user_id)
        if request.method == "DELETE":
            connection.execute(delete(db.grants).where(*match))
        elif not db.one(connection, db.grants, *match):
            db.add(connection, db.grants, case_id=case_id, user_id=user_id)
        db.record(
            connection,
            user["username"],
            "case_access_" + request.method.lower(),
            case_id,
            recipient["username"],
        )


@router.get("/cases/{case_id}/evidence")
def evidence_list(
    case_id: str,
    user: User,
    page: Page = 1,
    limit: Limit = 30,
    q: Search = "",
    integrity: Literal["unverified", "verified", "failed"] | None = None,
):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        query = select(db.evidence).where(db.evidence.c.case_id == case_id)
        if q:
            query = query.where(
                or_(
                    db.evidence.c.filename.icontains(q, autoescape=True),
                    db.evidence.c.sha256.startswith(q, autoescape=True),
                )
            )
        if integrity:
            query = query.where(db.evidence.c.integrity == integrity)
        return page_of(
            connection, query.order_by(db.evidence.c.imported_at.desc()), page, limit
        )


@router.post("/cases/{case_id}/evidence", status_code=201)
def evidence_upload(
    case_id: str,
    user: User,
    file: Annotated[UploadFile, File()],
    format: Annotated[str, Form(max_length=32)],
    source: Annotated[str, Form(min_length=1, max_length=4000)],
    collection_at: Annotated[str | None, Form(max_length=64)] = None,
    timezone_offset: Annotated[int, Form(ge=-840, le=840)] = 0,
    clock_offset: Annotated[int, Form(ge=-86400, le=86400)] = 0,
):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
    return vault.import_file(
        case_id,
        user["username"],
        file.file,
        file.filename,
        format,
        source,
        collection_at,
        timezone_offset,
        clock_offset,
        user=user,
    )


@router.get("/cases/{case_id}/evidence/{item_id}")
def evidence_detail(case_id: str, item_id: str, user: User):
    with db.transaction() as connection:
        security.require_case(connection, user, case_id)
        item = case_row(connection, db.evidence, case_id, item_id)
        vault.custody_append(
            connection,
            item_id,
            user["username"],
            "metadata_accessed",
            "Evidence detail opened",
        )
        item["verifications"] = [
            dict(row)
            for row in connection.execute(
                select(db.verifications)
                .where(db.verifications.c.evidence_id == item_id)
                .order_by(db.verifications.c.timestamp.desc())
            ).mappings()
        ]
        return item


@router.post("/cases/{case_id}/evidence/{item_id}/verify")
def verify(case_id: str, item_id: str, user: User):
    with db.transaction() as connection:
        security.require_case(connection, user, case_id)
        item = case_row(connection, db.evidence, case_id, item_id)
        return vault.verify(connection, item, user["username"])


@router.post("/cases/{case_id}/evidence/{item_id}/download")
def original(case_id: str, item_id: str, user: User):
    with db.transaction() as connection:
        security.require_case(connection, user, case_id)
        item = case_row(connection, db.evidence, case_id, item_id)
        path = vault.path_for(item_id)
        if not path.is_file():
            raise HTTPException(404, "Preserved bytes are missing")
        vault.custody_append(
            connection,
            item_id,
            user["username"],
            "download_requested",
            "Original bytes requested",
        )
        return FileResponse(
            path, filename=item["filename"], media_type="application/octet-stream"
        )


@router.get("/cases/{case_id}/evidence/{item_id}/custody")
def custody(case_id: str, item_id: str, user: User, page: Page = 1, limit: Limit = 50):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        item = case_row(connection, db.evidence, case_id, item_id)
        query = (
            select(db.custody)
            .where(db.custody.c.evidence_id == item_id)
            .order_by(db.custody.c.sequence)
        )
        return {
            **page_of(connection, query, page, limit),
            "verification": vault.custody_verify(connection, item),
        }


@router.post("/cases/{case_id}/evidence/{item_id}/custody")
def transfer(case_id: str, item_id: str, payload: schemas.CustodyAction, user: User):
    with db.transaction() as connection:
        security.require_case(connection, user, case_id)
        item = case_row(connection, db.evidence, case_id, item_id)
        if item["custodian"] != user["username"]:
            security.admin(user)
        target = db.one(
            connection,
            db.users,
            db.users.c.username == (payload.recipient or "").lower(),
        )
        if not target:
            raise HTTPException(422, "A registered recipient is required")
        security.require_case(connection, target, case_id)
        edit(connection, db.evidence, item_id, custodian=target["username"])
        return vault.custody_append(
            connection,
            item_id,
            user["username"],
            "transferred",
            f"{item['custodian']} → {target['username']}. {payload.reason}",
        )


@router.get("/cases/{case_id}/events")
@router.get("/cases/{case_id}/timeline")
def event_list(
    case_id: str,
    user: User,
    page: Page = 1,
    limit: Limit = 50,
    q: Search = "",
    category: Search = "",
    severity: schemas.Severity | None = None,
    host: Search = "",
    account: Search = "",
    evidence_id: Search = "",
    start: Search = "",
    end: Search = "",
):
    columns = db.events.c
    query = select(db.events).where(columns.case_id == case_id)
    if q:
        query = query.where(
            or_(
                *(
                    column.icontains(q, autoescape=True)
                    for column in (
                        columns.action,
                        columns.hostname,
                        columns.username,
                        columns.source_ref,
                    )
                )
            )
        )
    for column, value in (
        (columns.category, category),
        (columns.severity, severity),
        (columns.hostname, host),
        (columns.username, account),
        (columns.evidence_id, evidence_id),
    ):
        if value:
            query = query.where(column == value.casefold())
    for bound, lower in ((start, True), (end, False)):
        if bound:
            _, normalized, _ = parsers.timestamp(bound)
            if not normalized:
                raise HTTPException(422, "Use an ISO timestamp for time filters")
            query = query.where(
                columns.timestamp >= normalized
                if lower
                else columns.timestamp <= normalized
            )
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        return page_of(
            connection,
            query.order_by(columns.timestamp.is_(None), columns.timestamp, columns.id),
            page,
            limit,
        )


@router.get("/cases/{case_id}/timeline/extent")
def timeline_extent(case_id: str, user: User):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        timestamp = db.events.c.timestamp
        start, end, dated, total = connection.execute(
            select(
                func.min(timestamp),
                func.max(timestamp),
                func.count(timestamp),
                func.count(),
            ).where(db.events.c.case_id == case_id)
        ).one()
        return {"start": start, "end": end, "dated": dated, "undated": total - dated}


def linked_findings(case_id):
    return (
        select(db.finding_events.c.event_id, db.findings.c.id, db.findings.c.name)
        .join(db.findings, db.finding_events.c.finding_id == db.findings.c.id)
        .where(db.findings.c.case_id == case_id, db.findings.c.active.is_(True))
    )


def linked_indicators(case_id):
    return (
        select(db.matches.c.event_id, db.indicators.c.id, db.indicators.c.value)
        .join(db.indicators, db.matches.c.indicator_id == db.indicators.c.id)
        .where(db.matches.c.case_id == case_id, db.indicators.c.case_id == case_id)
    )


@router.get("/cases/{case_id}/events/{item_id}")
def event_detail(case_id: str, item_id: str, user: User):
    with db.transaction() as connection:
        security.require_case(connection, user, case_id)
        row = case_row(connection, db.events, case_id, item_id)
        vault.custody_append(
            connection,
            row["evidence_id"],
            user["username"],
            "event_accessed",
            row["source_ref"],
        )
        row["relationships"] = [
            dict(record)
            for record in connection.execute(
                select(db.relationships)
                .where(
                    db.relationships.c.case_id == case_id,
                    db.relationships.c.active.is_(True),
                    or_(
                        db.relationships.c.source_id == item_id,
                        db.relationships.c.target_id == item_id,
                    ),
                )
                .limit(100)
            ).mappings()
        ]
        row["findings"] = [
            {"id": found.id, "name": found.name}
            for found in connection.execute(
                linked_findings(case_id)
                .where(db.finding_events.c.event_id == item_id)
                .limit(100)
            )
        ]
        row["notes"] = [
            dict(record)
            for record in connection.execute(
                select(db.notes)
                .where(db.notes.c.case_id == case_id, db.notes.c.event_id == item_id)
                .limit(100)
            ).mappings()
        ]
        return row


@router.post("/cases/{case_id}/analyze")
def run_analysis(case_id: str, payload: schemas.Analyze, user: User):
    with db.transaction() as connection:
        security.require_case(connection, user, case_id)
        return analysis.analyze(connection, case_id, user["username"], payload.window)


@router.get("/cases/{case_id}/findings")
def findings(
    case_id: str,
    user: User,
    page: Page = 1,
    limit: Limit = 30,
    q: Search = "",
    history: bool = False,
):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        query = select(db.findings).where(db.findings.c.case_id == case_id)
        if not history:
            query = query.where(db.findings.c.active.is_(True))
        if q:
            query = query.where(db.findings.c.name.icontains(q, autoescape=True))
        result = page_of(
            connection,
            query.order_by(db.findings.c.timestamp.desc(), db.findings.c.id),
            page,
            limit,
        )
        result["items"] = [
            analysis.enrich_finding(connection, row) for row in result["items"]
        ]
        return result


@router.get("/cases/{case_id}/findings/{item_id}")
def finding(case_id: str, item_id: str, user: User):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        return analysis.enrich_finding(
            connection, case_row(connection, db.findings, case_id, item_id)
        )


@router.patch("/cases/{case_id}/findings/{item_id}")
def review_finding(
    case_id: str, item_id: str, payload: schemas.FindingReview, user: User
):
    with db.transaction() as connection:
        security.require_case(connection, user, case_id)
        case_row(connection, db.findings, case_id, item_id)
        row = edit(
            connection,
            db.findings,
            item_id,
            stage=payload.stage,
            review_reason=payload.reason,
            override=payload.override,
        )
        db.record(
            connection,
            user["username"],
            "finding_reviewed",
            case_id,
            f"{item_id} · {payload.stage} · {payload.reason}",
        )
        return analysis.enrich_finding(connection, row)


@router.get("/rules")
def rules(user: User):
    with db.transaction(write=False) as connection:
        return analysis.rule_config(connection)


@router.put("/rules/{rule_id}")
def save_rule(rule_id: str, payload: schemas.Rule, user: User):
    security.admin(user)
    if rule_id not in analysis.RULES:
        raise HTTPException(404, "Rule not found")
    if rule_id.startswith("auth_") and payload.threshold > 1000:
        raise HTTPException(422, "Authentication threshold must be at most 1,000")
    with db.transaction() as connection:
        if db.one(connection, db.rules, db.rules.c.id == rule_id):
            edit(connection, db.rules, rule_id, **payload.model_dump())
        else:
            db.add(connection, db.rules, id=rule_id, **payload.model_dump())
        db.record(connection, user["username"], "rule_configured", detail=rule_id)
        return next(
            row for row in analysis.rule_config(connection) if row["id"] == rule_id
        )


@router.get("/cases/{case_id}/correlation")
def graph(
    case_id: str,
    user: User,
    limit: Annotated[int, Query(ge=1, le=120)] = 30,
    relationship: Literal["observed", "inferred"] | None = None,
    kind: Search = "",
):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        edge_query = select(db.relationships).where(
            db.relationships.c.case_id == case_id, db.relationships.c.active.is_(True)
        )
        if relationship:
            edge_query = edge_query.where(db.relationships.c.kind == relationship)
        if kind:
            keys = (
                select(db.entity_events.c.event_id)
                .join(db.entities)
                .where(db.entities.c.case_id == case_id, db.entities.c.kind == kind)
            )
            if kind == "finding":
                keys = linked_findings(case_id).with_only_columns(
                    db.finding_events.c.event_id
                )
            elif kind == "indicator":
                keys = linked_indicators(case_id).with_only_columns(
                    db.matches.c.event_id
                )
            edge_query = edge_query.where(
                or_(
                    db.relationships.c.source_id.in_(keys),
                    db.relationships.c.target_id.in_(keys),
                )
            )
        edges = [
            dict(row)
            for row in connection.execute(
                edge_query.order_by(
                    db.relationships.c.confidence.desc(), db.relationships.c.id
                ).limit(limit + 1)
            ).mappings()
        ]
        limited = len(edges) > limit
        edges = edges[:limit]
        ids = {edge[key] for edge in edges for key in ("source_id", "target_id")}
        rows = [
            dict(row)
            for row in connection.execute(
                select(db.events)
                .where(db.events.c.case_id == case_id, db.events.c.id.in_(ids))
                .order_by(db.events.c.timestamp, db.events.c.id)
            ).mappings()
        ]
        attachments = [
            {"event_id": event_id, "id": item_id, "label": name, "kind": category}
            for category, links, column in (
                ("finding", linked_findings(case_id), db.finding_events.c.event_id),
                ("indicator", linked_indicators(case_id), db.matches.c.event_id),
            )
            for event_id, item_id, name in connection.execute(
                links.where(column.in_(ids)).order_by(column).limit(360)
            )
        ]
        return {
            "attachments": attachments,
            "nodes": [
                {
                    "id": r["id"],
                    "action": r["action"],
                    "hostname": r["hostname"],
                    "username": r["username"],
                    "evidence_id": r["evidence_id"],
                    "source_ref": r["source_ref"],
                    "timestamp": r["timestamp"],
                    "entities": sorted(analysis.entity_keys(r)),
                }
                for r in rows
            ],
            "edges": edges,
            "limited": limited,
        }


@router.patch("/cases/{case_id}/correlation/{item_id}")
def review_graph(
    case_id: str, item_id: str, payload: schemas.RelationshipReview, user: User
):
    with db.transaction() as connection:
        security.require_case(connection, user, case_id)
        case_row(connection, db.relationships, case_id, item_id)
        result = edit(connection, db.relationships, item_id, **payload.model_dump())
        db.record(
            connection, user["username"], "relationship_reviewed", case_id, item_id
        )
        return result


@router.get("/cases/{case_id}/entities")
def entities(
    case_id: str,
    user: User,
    page: Page = 1,
    limit: Limit = 50,
    kind: Search = "",
    q: Search = "",
):
    query = select(db.entities).where(db.entities.c.case_id == case_id)
    if kind:
        query = query.where(db.entities.c.kind == kind)
    if q:
        query = query.where(db.entities.c.value.icontains(q, autoescape=True))
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        result = page_of(
            connection,
            query.order_by(db.entities.c.kind, db.entities.c.value),
            page,
            limit,
        )
        for row in result["items"]:
            row["event_ids"] = list(
                connection.scalars(
                    select(db.entity_events.c.event_id)
                    .where(db.entity_events.c.entity_id == row["id"])
                    .limit(30)
                )
            )
        return result


@router.get("/cases/{case_id}/network")
def network(case_id: str, user: User):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        columns = db.events.c
        network_records = select(
            columns.protocol,
            columns.source_ip,
            columns.destination_ip,
            columns.source_port,
            columns.destination_port,
            columns.domain,
            columns.bytes,
        ).where(columns.case_id == case_id, columns.category == "network")
        result = analysis.network(connection.execute(network_records).mappings())
        result["matches"] = connection.scalar(
            select(func.count())
            .select_from(db.matches.join(db.events))
            .where(db.matches.c.case_id == case_id, db.events.c.category == "network")
        )
        return result


@router.get("/cases/{case_id}/intelligence")
def indicators(case_id: str, user: User, page: Page = 1, limit: Limit = 50):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        result = page_of(
            connection,
            select(db.indicators)
            .where(db.indicators.c.case_id == case_id)
            .order_by(db.indicators.c.created_at.desc()),
            page,
            limit,
        )
        for row in result["items"]:
            query = select(db.matches.c.event_id).where(
                db.matches.c.indicator_id == row["id"]
            )
            row["event_ids"] = list(connection.scalars(query.limit(30)))
            row["match_count"] = connection.scalar(
                select(func.count()).select_from(query.subquery())
            )
        return result


def save_indicator(connection, case_id, payload):
    try:
        kind, value = analysis.canonical_indicator(payload.kind, payload.value)
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    expires = None
    if payload.expires_at:
        _, expires, quality = parsers.timestamp(payload.expires_at)
        if quality != "explicit":
            raise HTTPException(422, "Expiration must include an explicit timezone")
    if db.one(
        connection,
        db.indicators,
        db.indicators.c.case_id == case_id,
        db.indicators.c.kind == kind,
        db.indicators.c.value == value,
    ):
        raise HTTPException(409, f"Duplicate indicator: {value}")
    return db.add(
        connection,
        db.indicators,
        case_id=case_id,
        kind=kind,
        value=value,
        source=payload.source,
        confidence=payload.confidence,
        description=payload.description,
        created_at=db.utc(),
        expires_at=expires,
        tags=payload.tags,
    )


@router.post("/cases/{case_id}/intelligence", status_code=201)
def add_indicator(case_id: str, payload: schemas.Indicator, user: User):
    with db.transaction() as connection:
        security.require_case(connection, user, case_id)
        result = save_indicator(connection, case_id, payload)
        db.record(
            connection, user["username"], "indicator_added", case_id, result["id"]
        )
        return result


@router.post("/cases/{case_id}/intelligence/import", status_code=201)
def indicator_import(case_id: str, user: User, file: Annotated[UploadFile, File()]):
    from pydantic import ValidationError

    with db.transaction() as connection:
        security.require_case(connection, user, case_id)
        try:
            text = file.file.read(1_048_577)
            if len(text) > 1_048_576:
                raise HTTPException(413, "Indicator file limit is 1 MiB")
            text = text.decode("utf-8-sig")
            if (file.filename or "").lower().endswith(".csv"):
                rows = list(csv.DictReader(io.StringIO(text), strict=True))
                for row in rows:
                    row["tags"] = [
                        part.strip()
                        for part in (row.get("tags") or "").split("|")
                        if part.strip()
                    ]
                    if not row.get("expires_at"):
                        row.pop("expires_at", None)
                    if not row.get("confidence"):
                        row.pop("confidence", None)
            else:
                rows = parsers.json_record(text)
            if not isinstance(rows, list) or not 1 <= len(rows) <= 1000:
                raise ValueError("Import requires 1 to 1,000 indicator records")
            for index, row in enumerate(rows, 1):
                try:
                    save_indicator(
                        connection, case_id, schemas.Indicator.model_validate(row)
                    )
                except (ValidationError, HTTPException) as error:
                    raise ValueError(
                        f"Invalid or duplicate indicator at record {index}"
                    ) from error
        except (ValueError, TypeError, csv.Error, RecursionError) as error:
            raise HTTPException(422, str(error)) from error
        db.record(
            connection, user["username"], "indicators_imported", case_id, str(len(rows))
        )
        return {"imported": len(rows)}


@router.get("/cases/{case_id}/notes")
def notes(case_id: str, user: User, page: Page = 1, limit: Limit = 50):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        return page_of(
            connection,
            select(db.notes)
            .where(db.notes.c.case_id == case_id)
            .order_by(db.notes.c.timestamp.desc()),
            page,
            limit,
        )


@router.post("/cases/{case_id}/notes", status_code=201)
def add_note(case_id: str, payload: schemas.Note, user: User):
    with db.transaction() as connection:
        security.require_case(connection, user, case_id)
        if payload.event_id:
            case_row(connection, db.events, case_id, payload.event_id)
        result = db.add(
            connection,
            db.notes,
            actor=user["username"],
            timestamp=db.utc(),
            case_id=case_id,
            **payload.model_dump(),
        )
        db.record(connection, user["username"], "note_added", case_id, result["id"])
        return result


@router.get("/cases/{case_id}/activity")
def activity(case_id: str, user: User, page: Page = 1, limit: Limit = 25):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        return page_of(
            connection,
            select(db.audit)
            .where(db.audit.c.case_id == case_id)
            .order_by(db.audit.c.timestamp.desc()),
            page,
            limit,
        )


@router.get("/cases/{case_id}/reports")
def reports(case_id: str, user: User, page: Page = 1, limit: Limit = 25):
    with db.transaction(write=False) as connection:
        security.require_case(connection, user, case_id)
        return page_of(
            connection,
            select(db.reports)
            .where(db.reports.c.case_id == case_id)
            .order_by(db.reports.c.timestamp.desc()),
            page,
            limit,
        )


@router.post("/cases/{case_id}/reports/{format}")
def report(
    case_id: str,
    format: Literal["pdf", "html", "json", "events.csv", "findings.csv"],
    user: User,
):
    from hashlib import sha256

    with db.transaction() as connection:
        case = security.require_case(connection, user, case_id)
        snapshot = reporting.snapshot(connection, case)
        content = reporting.render(snapshot, format)
        db.add(
            connection,
            db.reports,
            case_id=case_id,
            actor=user["username"],
            timestamp=snapshot["generated_at"],
            format=format,
            sha256=sha256(content).hexdigest(),
        )
        for item in snapshot["evidence"]:
            vault.custody_append(
                connection, item["id"], user["username"], "report_exported", format
            )
        db.record(connection, user["username"], "report_exported", case_id, format)
    name = (
        f"threattrace-{case_id}.{format}"
        if "." not in format
        else f"threattrace-{case_id}-{format}"
    )
    return Response(
        content,
        media_type=reporting.MIME[format],
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
        },
    )


@router.get("/dashboard")
def dashboard(user: User):
    accessible = select(db.cases.c.id).where(security.scope(user))
    active = db.cases.c.status.in_(("open", "under_investigation", "awaiting_evidence"))

    def count(connection, table, *predicates):
        key = table.c.id if table is db.cases else table.c.case_id
        return connection.scalar(
            select(func.count())
            .select_from(table)
            .where(key.in_(accessible), *predicates)
        )

    with db.transaction(write=False) as connection:
        valid = db.findings.c.active.is_(True)
        evidence_status = Counter(
            dict(
                connection.execute(
                    select(db.evidence.c.integrity, func.count())
                    .where(db.evidence.c.case_id.in_(accessible))
                    .group_by(db.evidence.c.integrity)
                ).all()
            )
        )
        signal = Counter(
            dict(
                connection.execute(
                    select(db.findings.c.severity, func.count())
                    .where(db.findings.c.case_id.in_(accessible), valid)
                    .group_by(db.findings.c.severity)
                ).all()
            )
        )
        day = func.substr(db.events.c.timestamp, 1, 10)
        trend = connection.execute(
            select(day, func.count())
            .where(
                db.events.c.case_id.in_(accessible), db.events.c.timestamp.is_not(None)
            )
            .group_by(day)
            .order_by(day.desc())
            .limit(14)
        ).all()
        recent = [
            dict(row)
            for row in connection.execute(
                select(db.audit, db.cases.c.title.label("case_title"))
                .join(db.cases, db.audit.c.case_id == db.cases.c.id)
                .where(db.audit.c.case_id.in_(accessible))
                .order_by(db.audit.c.timestamp.desc())
                .limit(6)
            ).mappings()
        ]
        active_cases = [
            dict(row)
            for row in connection.execute(
                select(db.cases)
                .where(db.cases.c.id.in_(accessible), active)
                .order_by(db.cases.c.updated_at.desc())
                .limit(5)
            ).mappings()
        ]
        recent_findings = [
            dict(row)
            for row in connection.execute(
                select(db.findings, db.cases.c.title.label("case_title"))
                .join(db.cases)
                .where(db.findings.c.case_id.in_(accessible), valid)
                .order_by(db.findings.c.timestamp.desc())
                .limit(5)
            ).mappings()
        ]
        return {
            "active_cases": count(connection, db.cases, active),
            "evidence": sum(evidence_status.values()),
            "verified": evidence_status["verified"],
            "integrity_failures": evidence_status["failed"],
            "critical": signal["critical"],
            "unresolved": count(
                connection,
                db.findings,
                valid,
                db.findings.c.stage.in_(("observation", "suspicious")),
            ),
            "events": count(connection, db.events),
            "matches": count(connection, db.matches),
            "evidence_status": evidence_status,
            "severity": signal,
            "trend": [tuple(row) for row in reversed(trend)],
            "recent_activity": recent,
            "active": active_cases,
            "recent_findings": recent_findings,
        }


@router.get("/research")
def research(user: User):
    path = settings.ROOT / "research" / "results" / "results.json"
    if not path.is_file():
        return {"available": False}
    return {"available": True, **json.loads(path.read_text(encoding="utf-8"))}


@router.get("/research/{format}")
def research_export(format: Literal["json", "csv"], user: User):
    path = settings.ROOT / "research" / "results" / f"results.{format}"
    if not path.is_file():
        raise HTTPException(404, "No research results are available")
    return FileResponse(path, filename=path.name)
