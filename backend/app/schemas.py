from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Name = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=160)
]
Username = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$"
    ),
]
Reason = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)
]
Severity = Literal["info", "low", "medium", "high", "critical"]
Status = Literal[
    "open", "under_investigation", "awaiting_evidence", "resolved", "closed", "archived"
]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Input):
    username: Username
    password: str = Field(min_length=1, max_length=256)


class UserCreate(Login):
    password: str = Field(min_length=12, max_length=256)
    role: Literal["investigator", "administrator"] = "investigator"


class CaseInput(Input):
    title: Name
    description: str = Field(default="", max_length=20000)
    investigator: Name
    classification: Name = "Unclassified"
    severity: Severity = "medium"
    status: Status = "open"


class Note(Input):
    body: Reason
    event_id: str | None = Field(default=None, max_length=64)


class RelationshipReview(Input):
    review: Literal["confirmed", "rejected", "pending"]
    reason: Reason


class FindingReview(Input):
    stage: Literal["observation", "suspicious", "confirmed", "dismissed"]
    reason: Reason
    override: int | None = Field(default=None, ge=0, le=100)


class CustodyAction(Input):
    reason: Reason
    recipient: Username | None = None


class Analyze(Input):
    window: int = Field(default=300, ge=1, le=86400)


class Rule(Input):
    enabled: bool
    threshold: int = Field(ge=1, le=2**31 - 1)
    window: int = Field(ge=1, le=86400)


class Indicator(Input):
    kind: Literal[
        "ip", "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "sha512"
    ]
    value: str = Field(min_length=1, max_length=4096)
    source: Name
    confidence: int = Field(default=50, ge=0, le=100)
    description: str = Field(default="", max_length=4000)
    expires_at: str | None = Field(default=None, max_length=64)
    tags: list[Name] = Field(default_factory=list, max_length=20)
