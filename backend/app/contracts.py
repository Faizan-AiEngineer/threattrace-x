"""Public response contracts for the versioned investigation API."""

from typing import Any, Literal

from pydantic import BaseModel

from .schemas import Severity, Status

Role = Literal["administrator", "investigator"]
Integrity = Literal["unverified", "verified", "failed"]


class Page[T](BaseModel):
    items: list[T]
    total: int
    page: int
    limit: int


class Health(BaseModel):
    status: Literal["ok"]
    version: str


class User(BaseModel):
    id: str
    username: str
    role: Role
    created_at: str
    disabled_at: str | None
    password_change_required: bool


class Grant(BaseModel):
    id: str
    user_id: str
    username: str
    role: Role
    disabled_at: str | None
    created_at: str | None


class CaseGrants(Page[Grant]):
    owner: User


class Case(BaseModel):
    id: str
    title: str
    description: str
    owner_id: str
    investigator: str
    created_at: str
    updated_at: str
    classification: str
    severity: Severity
    status: Status
    synthetic: bool


class AuditRecord(BaseModel):
    id: str
    actor: str
    action: str
    timestamp: str
    case_id: str | None
    detail: str


class VerificationRecord(BaseModel):
    id: str
    evidence_id: str
    actor: str
    timestamp: str
    actual_hash: str | None
    status: Integrity


class ParseError(BaseModel):
    source_ref: str
    reason: str


class EvidenceStats(BaseModel):
    records: int
    parsed: int
    malformed: int
    uncertain: int | None = None
    errors: list[ParseError]
    failed: bool
    truncated: bool | None = None


class Evidence(BaseModel):
    id: str
    case_id: str
    filename: str
    size: int
    format: str
    sha256: str
    collection_at: str | None
    imported_at: str
    source: str
    uploader: str
    custodian: str
    integrity: Integrity
    parser_version: str
    state: str
    stats: EvidenceStats
    clock_offset: int
    timezone_offset: int
    custody_count: int
    custody_head: str | None


class EvidenceDetail(Evidence):
    verifications: list[VerificationRecord]


class Verification(BaseModel):
    status: Integrity
    expected_hash: str
    actual_hash: str | None


class CustodyRecord(BaseModel):
    id: str
    evidence_id: str
    sequence: int
    actor: str
    action: str
    timestamp: str
    reason: str
    previous_hash: str | None
    record_hash: str


class CustodyResult(BaseModel):
    valid: bool
    records: int
    failed_at: int | None
    reason: str | None


class CustodyPage(Page[CustodyRecord]):
    verification: CustodyResult


class TimelineExtent(BaseModel):
    start: str | None
    end: str | None
    dated: int
    undated: int


class RelationshipAttribute(BaseModel):
    kind: str
    value: str
    seconds_apart: float


class Relationship(BaseModel):
    id: str
    case_id: str
    source_id: str
    target_id: str
    kind: Literal["observed", "inferred"]
    attributes: list[RelationshipAttribute]
    explanation: str
    confidence: float
    version: str
    review: str
    reason: str
    active: bool


class GraphNode(BaseModel):
    id: str
    action: str
    category: str
    severity: Severity
    hostname: str | None
    username: str | None
    outcome: str | None
    evidence_id: str
    source_ref: str
    timestamp: str | None
    entities: list[tuple[str, str]]


class GraphAttachment(BaseModel):
    event_id: str
    id: str
    label: str
    kind: Literal["finding", "indicator"]


class Graph(BaseModel):
    nodes: list[GraphNode]
    edges: list[Relationship]
    attachments: list[GraphAttachment]
    sources: dict[str, str]
    limited: bool


class Note(BaseModel):
    id: str
    case_id: str
    event_id: str | None
    actor: str
    timestamp: str
    body: str


class Event(BaseModel):
    id: str
    case_id: str
    evidence_id: str
    timestamp: str | None
    original_timestamp: str | None
    time_quality: str
    source_type: str
    category: str
    action: str
    source_ip: str | None
    destination_ip: str | None
    protocol: str | None
    hostname: str | None
    username: str | None
    process_name: str | None
    file_path: str | None
    file_hash: str | None
    process_id: str | None
    domain: str | None
    url: str | None
    outcome: str | None
    source_port: int | None
    destination_port: int | None
    bytes: int | None
    severity: Severity
    source_ref: str
    metadata: dict[str, Any]
    clock_offset: int


class FindingLink(BaseModel):
    id: str
    name: str


class EventDetail(Event):
    relationships: list[Relationship]
    findings: list[FindingLink]
    notes: list[Note]


class AnalysisResult(BaseModel):
    events: int
    excluded_integrity_failed: int
    findings: int
    relationships: int
    matches: int


class ConfidenceContribution(BaseModel):
    weight: float
    value: float | None
    contribution: float | None


class Confidence(BaseModel):
    score: int | None
    category: str
    components: dict[str, ConfidenceContribution]


class FindingRow(FindingLink):
    case_id: str
    rule_id: str
    version: str
    severity: Severity
    stage: str
    explanation: str
    steps: str
    limitations: str
    technique: str | None
    confidence: Confidence
    timestamp: str | None
    active: bool
    review_reason: str
    override: int | None


class Finding(FindingRow):
    evidence_ids: list[str]
    event_ids: list[str]


class Rule(BaseModel):
    id: str
    name: str
    severity: Severity
    technique: str | None
    version: str
    enabled: bool
    threshold: int
    window: int


class Entity(BaseModel):
    id: str
    case_id: str
    kind: str
    value: str
    event_ids: list[str]


class NetworkFlow(BaseModel):
    source: str
    destination: str
    protocol: str
    source_port: int | None
    destination_port: int | None
    records: int


class Network(BaseModel):
    records: int
    bytes: int
    matches: int
    protocols: list[tuple[str, int]]
    sources: list[tuple[str, int]]
    destinations: list[tuple[str, int]]
    ports: list[tuple[str, int]]
    dns: list[tuple[str, int]]
    flows: list[NetworkFlow]


class Indicator(BaseModel):
    id: str
    case_id: str
    kind: str
    value: str
    source: str
    confidence: int
    description: str
    created_at: str
    expires_at: str | None
    tags: list[str]


class IndicatorMatches(Indicator):
    match_count: int
    event_ids: list[str]


class IndicatorImport(BaseModel):
    imported: int


class Report(BaseModel):
    id: str
    case_id: str
    actor: str
    timestamp: str
    format: str
    sha256: str


class RecentActivity(AuditRecord):
    case_title: str


class RecentFinding(FindingRow):
    case_title: str


class Dashboard(BaseModel):
    active_cases: int
    evidence: int
    verified: int
    integrity_failures: int
    critical: int
    unresolved: int
    events: int
    matches: int
    evidence_status: dict[str, int]
    severity: dict[str, int]
    trend: list[tuple[str, int]]
    recent_activity: list[RecentActivity]
    active: list[Case]
    recent_findings: list[RecentFinding]


class ResearchUnavailable(BaseModel):
    available: Literal[False]


class BenchmarkRow(BaseModel):
    experiment: str
    method: str
    condition: str
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    false_positive_rate: float | None = None
    tp: int | None = None
    fp: int | None = None
    tn: int | None = None
    fn: int | None = None
    order_errors: int | None = None
    result: str | None = None
    events: int | None = None
    seconds: float | None = None
    correlation_seconds: float | None = None
    throughput: float | None = None
    peak_mib: float | None = None
    relationships: int | None = None
    score: int | None = None
    category: str | None = None
    seed: int | None = None


class Research(BaseModel):
    available: Literal[True]
    seed: int
    generated_at: str
    descriptions: dict[str, str]
    limitations: list[str]
    configuration: dict[str, str | int]
    rows: list[BenchmarkRow]


class Estimate(BaseModel):
    mean: float
    sample_sd: float


class MethodSummary(BaseModel):
    experiment: str
    method: str
    precision: Estimate
    recall: Estimate
    f1: Estimate
    false_positive_rate: Estimate


class MultiSeed(BaseModel):
    available: Literal[True]
    seeds: list[int]
    rows: list[BenchmarkRow]
    summary: list[MethodSummary]
