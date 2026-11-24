from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    insert,
    select,
)

from .settings import DATA, DB_URL, VAULT

meta = MetaData()
engine = create_engine(
    DB_URL, connect_args={"timeout": 30} if DB_URL.startswith("sqlite:") else {}
)


if engine.dialect.name == "sqlite":

    @event.listens_for(engine, "connect")
    def sqlite_constraints(connection, _):
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")


def field(name, kind=String, *, required=True, **kwargs):
    return Column(name, kind, nullable=not required, **kwargs)


def ref(name, target, *, required=True, **kwargs):
    return Column(
        name,
        String,
        ForeignKey(target, ondelete="CASCADE"),
        nullable=not required,
        **kwargs,
    )


def table(name, *fields):
    return Table(name, meta, field("id", primary_key=True), *fields)


users = table(
    "users",
    field("username", unique=True),
    field("password_hash"),
    field("role"),
    field("created_at"),
)
sessions = table(
    "sessions", ref("user_id", "users.id", index=True), field("expires_at", index=True)
)
cases = table(
    "cases",
    field("title"),
    field("description", Text),
    ref("owner_id", "users.id"),
    field("investigator"),
    field("created_at"),
    field("updated_at"),
    field("classification"),
    field("severity"),
    field("status", index=True),
    field("synthetic", Boolean),
)
grants = table(
    "case_access",
    ref("case_id", "cases.id"),
    ref("user_id", "users.id", index=True),
    UniqueConstraint("case_id", "user_id"),
)
evidence = table(
    "evidence",
    ref("case_id", "cases.id", index=True),
    field("filename"),
    field("size", Integer),
    field("format"),
    field("sha256"),
    field("collection_at", required=False),
    field("imported_at"),
    field("source", Text),
    field("uploader"),
    field("custodian"),
    field("integrity"),
    field("parser_version"),
    field("state"),
    field("stats", JSON),
    field("clock_offset", Integer),
    field("timezone_offset", Integer),
    field("custody_count", Integer),
    field("custody_head", required=False),
    UniqueConstraint("case_id", "sha256"),
)
verifications = table(
    "evidence_verifications",
    ref("evidence_id", "evidence.id", index=True),
    field("actor"),
    field("timestamp"),
    field("actual_hash", required=False),
    field("status"),
)
custody = table(
    "custody",
    ref("evidence_id", "evidence.id", index=True),
    field("sequence", Integer),
    field("actor"),
    field("action"),
    field("timestamp"),
    field("reason", Text),
    field("previous_hash", required=False),
    field("record_hash"),
    UniqueConstraint("evidence_id", "sequence"),
)
events = table(
    "events",
    ref("case_id", "cases.id"),
    ref("evidence_id", "evidence.id", index=True),
    field("timestamp", required=False),
    field("original_timestamp", required=False),
    field("time_quality"),
    field("source_type"),
    field("category"),
    field("action"),
    *(
        field(key, required=False)
        for key in (
            "source_ip",
            "destination_ip",
            "protocol",
            "hostname",
            "username",
            "process_name",
            "file_path",
            "file_hash",
            "process_id",
            "domain",
            "url",
            "outcome",
        )
    ),
    *(
        field(key, Integer, required=False)
        for key in ("source_port", "destination_port", "bytes")
    ),
    field("severity"),
    field("source_ref"),
    field("metadata", JSON),
    field("clock_offset", Integer),
    UniqueConstraint("evidence_id", "source_ref"),
)
Index("ix_events_case_time", events.c.case_id, events.c.timestamp, events.c.id)
entities = table(
    "entities",
    ref("case_id", "cases.id", index=True),
    field("kind"),
    field("value"),
    UniqueConstraint("case_id", "kind", "value"),
)
entity_events = table(
    "entity_events",
    ref("entity_id", "entities.id", index=True),
    ref("event_id", "events.id", index=True),
    UniqueConstraint("entity_id", "event_id"),
)
relationships = table(
    "relationships",
    ref("case_id", "cases.id", index=True),
    ref("source_id", "events.id"),
    ref("target_id", "events.id"),
    field("kind"),
    field("attributes", JSON),
    field("explanation"),
    field("confidence", Float),
    field("version"),
    field("review"),
    field("reason", Text),
    field("active", Boolean),
    UniqueConstraint("case_id", "source_id", "target_id"),
)
rules = table(
    "rules",
    field("enabled", Boolean),
    field("threshold", Integer),
    field("window", Integer),
)
findings = table(
    "findings",
    ref("case_id", "cases.id", index=True),
    field("rule_id"),
    field("version"),
    field("name"),
    field("severity"),
    field("stage"),
    field("explanation", Text),
    field("steps", Text),
    field("limitations", Text),
    field("technique", required=False),
    field("confidence", JSON),
    field("timestamp", required=False),
    field("active", Boolean),
    field("review_reason", Text),
    field("override", Integer, required=False),
)
finding_events = table(
    "finding_events",
    ref("finding_id", "findings.id", index=True),
    ref("event_id", "events.id"),
    UniqueConstraint("finding_id", "event_id"),
)
finding_evidence = table(
    "finding_evidence",
    ref("finding_id", "findings.id", index=True),
    ref("evidence_id", "evidence.id"),
    UniqueConstraint("finding_id", "evidence_id"),
)
indicators = table(
    "indicators",
    ref("case_id", "cases.id", index=True),
    field("kind"),
    field("value"),
    field("source"),
    field("confidence", Integer),
    field("description", Text),
    field("created_at"),
    field("expires_at", required=False),
    field("tags", JSON),
    UniqueConstraint("case_id", "kind", "value"),
)
matches = table(
    "indicator_matches",
    ref("case_id", "cases.id", index=True),
    ref("indicator_id", "indicators.id"),
    ref("event_id", "events.id"),
    UniqueConstraint("indicator_id", "event_id"),
)
notes = table(
    "notes",
    ref("case_id", "cases.id", index=True),
    ref("event_id", "events.id", required=False),
    field("actor"),
    field("timestamp"),
    field("body", Text),
)
reports = table(
    "reports",
    ref("case_id", "cases.id", index=True),
    field("actor"),
    field("timestamp"),
    field("format"),
    field("sha256"),
)
audit = table(
    "audit",
    ref("case_id", "cases.id", required=False, index=True),
    field("actor"),
    field("action"),
    field("timestamp"),
    field("detail", Text),
)
experiments = table(
    "research_experiments",
    field("timestamp"),
    field("seed", Integer),
    field("results", JSON),
)


def uid():
    return str(uuid4())


def utc(value=None):
    return (
        (value or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="microseconds")
    )


def initialize():
    DATA.mkdir(parents=True, exist_ok=True)
    VAULT.mkdir(parents=True, exist_ok=True)
    from alembic import command
    from alembic.config import Config

    config = Config()
    config.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[1] / "migrations")
    )
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


@contextmanager
def transaction(*, write=True):
    with engine.connect() as connection:
        if engine.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield connection
            if write:
                connection.commit()
        except BaseException:
            connection.rollback()
            raise


def add(connection, target, **values):
    values.setdefault("id", uid())
    connection.execute(insert(target).values(**values))
    return values


def one(connection, target, *conditions):
    row = connection.execute(select(target).where(*conditions)).mappings().first()
    return dict(row) if row else None


def record(connection, actor, action, case_id=None, detail=""):
    return add(
        connection,
        audit,
        actor=actor,
        action=action,
        case_id=case_id,
        timestamp=utc(),
        detail=detail,
    )
