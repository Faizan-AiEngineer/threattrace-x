"""Initial investigation schema."""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None


def upgrade():
    op.create_table(
        "research_experiments",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.Column("seed", sa.Integer(), nullable=False),
        sa.Column("results", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "rules",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("threshold", sa.Integer(), nullable=False),
        sa.Column("window", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "cases",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("owner_id", sa.String(), nullable=False),
        sa.Column("investigator", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("classification", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_cases_status"), "cases", ["status"], unique=False)
    op.create_table(
        "sessions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_sessions_expires_at"), "sessions", ["expires_at"], unique=False
    )
    op.create_index(op.f("ix_sessions_user_id"), "sessions", ["user_id"], unique=False)
    op.create_table(
        "audit",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=True),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_audit_case_id"), "audit", ["case_id"], unique=False)
    op.create_table(
        "case_access",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "user_id"),
    )
    op.create_index(
        op.f("ix_case_access_user_id"), "case_access", ["user_id"], unique=False
    )
    op.create_table(
        "entities",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "kind", "value"),
    )
    op.create_index(op.f("ix_entities_case_id"), "entities", ["case_id"], unique=False)
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("filename", sa.String(), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("format", sa.String(), nullable=False),
        sa.Column("sha256", sa.String(), nullable=False),
        sa.Column("collection_at", sa.String(), nullable=True),
        sa.Column("imported_at", sa.String(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("uploader", sa.String(), nullable=False),
        sa.Column("custodian", sa.String(), nullable=False),
        sa.Column("integrity", sa.String(), nullable=False),
        sa.Column("parser_version", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("stats", sa.JSON(), nullable=False),
        sa.Column("clock_offset", sa.Integer(), nullable=False),
        sa.Column("timezone_offset", sa.Integer(), nullable=False),
        sa.Column("custody_count", sa.Integer(), nullable=False),
        sa.Column("custody_head", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "sha256"),
    )
    op.create_index(op.f("ix_evidence_case_id"), "evidence", ["case_id"], unique=False)
    op.create_table(
        "findings",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("stage", sa.String(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("steps", sa.Text(), nullable=False),
        sa.Column("limitations", sa.Text(), nullable=False),
        sa.Column("technique", sa.String(), nullable=True),
        sa.Column("confidence", sa.JSON(), nullable=False),
        sa.Column("timestamp", sa.String(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("review_reason", sa.Text(), nullable=False),
        sa.Column("override", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_findings_case_id"), "findings", ["case_id"], unique=False)
    op.create_table(
        "indicators",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "kind", "value"),
    )
    op.create_index(
        op.f("ix_indicators_case_id"), "indicators", ["case_id"], unique=False
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.Column("format", sa.String(), nullable=False),
        sa.Column("sha256", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_reports_case_id"), "reports", ["case_id"], unique=False)
    op.create_table(
        "custody",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("evidence_id", sa.String(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("previous_hash", sa.String(), nullable=True),
        sa.Column("record_hash", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evidence_id", "sequence"),
    )
    op.create_index(
        op.f("ix_custody_evidence_id"), "custody", ["evidence_id"], unique=False
    )
    op.create_table(
        "events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("evidence_id", sa.String(), nullable=False),
        sa.Column("timestamp", sa.String(), nullable=True),
        sa.Column("original_timestamp", sa.String(), nullable=True),
        sa.Column("time_quality", sa.String(), nullable=False),
        sa.Column("source_type", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("source_ip", sa.String(), nullable=True),
        sa.Column("destination_ip", sa.String(), nullable=True),
        sa.Column("protocol", sa.String(), nullable=True),
        sa.Column("hostname", sa.String(), nullable=True),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("process_name", sa.String(), nullable=True),
        sa.Column("file_path", sa.String(), nullable=True),
        sa.Column("file_hash", sa.String(), nullable=True),
        sa.Column("process_id", sa.String(), nullable=True),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("url", sa.String(), nullable=True),
        sa.Column("outcome", sa.String(), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("bytes", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("source_ref", sa.String(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("clock_offset", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evidence_id", "source_ref"),
    )
    op.create_index(
        "ix_events_case_time", "events", ["case_id", "timestamp", "id"], unique=False
    )
    op.create_index(
        op.f("ix_events_evidence_id"), "events", ["evidence_id"], unique=False
    )
    op.create_table(
        "evidence_verifications",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("evidence_id", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.Column("actual_hash", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_evidence_verifications_evidence_id"),
        "evidence_verifications",
        ["evidence_id"],
        unique=False,
    )
    op.create_table(
        "finding_evidence",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("evidence_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", "evidence_id"),
    )
    op.create_index(
        op.f("ix_finding_evidence_finding_id"),
        "finding_evidence",
        ["finding_id"],
        unique=False,
    )
    op.create_table(
        "entity_events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("entity_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_id", "event_id"),
    )
    op.create_index(
        op.f("ix_entity_events_entity_id"), "entity_events", ["entity_id"], unique=False
    )
    op.create_index(
        op.f("ix_entity_events_event_id"), "entity_events", ["event_id"], unique=False
    )
    op.create_table(
        "finding_events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", "event_id"),
    )
    op.create_index(
        op.f("ix_finding_events_finding_id"),
        "finding_events",
        ["finding_id"],
        unique=False,
    )
    op.create_table(
        "indicator_matches",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("indicator_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["indicator_id"], ["indicators.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("indicator_id", "event_id"),
    )
    op.create_index(
        op.f("ix_indicator_matches_case_id"),
        "indicator_matches",
        ["case_id"],
        unique=False,
    )
    op.create_table(
        "notes",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=True),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_notes_case_id"), "notes", ["case_id"], unique=False)
    op.create_table(
        "relationships",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("case_id", sa.String(), nullable=False),
        sa.Column("source_id", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("explanation", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("version", sa.String(), nullable=False),
        sa.Column("review", sa.String(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_id"], ["events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "source_id", "target_id"),
    )
    op.create_index(
        op.f("ix_relationships_case_id"), "relationships", ["case_id"], unique=False
    )


def downgrade():
    op.drop_index(op.f("ix_relationships_case_id"), table_name="relationships")
    op.drop_table("relationships")
    op.drop_index(op.f("ix_notes_case_id"), table_name="notes")
    op.drop_table("notes")
    op.drop_index(op.f("ix_indicator_matches_case_id"), table_name="indicator_matches")
    op.drop_table("indicator_matches")
    op.drop_index(op.f("ix_finding_events_finding_id"), table_name="finding_events")
    op.drop_table("finding_events")
    op.drop_index(op.f("ix_entity_events_event_id"), table_name="entity_events")
    op.drop_index(op.f("ix_entity_events_entity_id"), table_name="entity_events")
    op.drop_table("entity_events")
    op.drop_index(op.f("ix_finding_evidence_finding_id"), table_name="finding_evidence")
    op.drop_table("finding_evidence")
    op.drop_index(
        op.f("ix_evidence_verifications_evidence_id"),
        table_name="evidence_verifications",
    )
    op.drop_table("evidence_verifications")
    op.drop_index(op.f("ix_events_evidence_id"), table_name="events")
    op.drop_index("ix_events_case_time", table_name="events")
    op.drop_table("events")
    op.drop_index(op.f("ix_custody_evidence_id"), table_name="custody")
    op.drop_table("custody")
    op.drop_index(op.f("ix_reports_case_id"), table_name="reports")
    op.drop_table("reports")
    op.drop_index(op.f("ix_indicators_case_id"), table_name="indicators")
    op.drop_table("indicators")
    op.drop_index(op.f("ix_findings_case_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index(op.f("ix_evidence_case_id"), table_name="evidence")
    op.drop_table("evidence")
    op.drop_index(op.f("ix_entities_case_id"), table_name="entities")
    op.drop_table("entities")
    op.drop_index(op.f("ix_case_access_user_id"), table_name="case_access")
    op.drop_table("case_access")
    op.drop_index(op.f("ix_audit_case_id"), table_name="audit")
    op.drop_table("audit")
    op.drop_index(op.f("ix_sessions_user_id"), table_name="sessions")
    op.drop_index(op.f("ix_sessions_expires_at"), table_name="sessions")
    op.drop_table("sessions")
    op.drop_index(op.f("ix_cases_status"), table_name="cases")
    op.drop_table("cases")
    op.drop_table("users")
    op.drop_table("rules")
    op.drop_table("research_experiments")
