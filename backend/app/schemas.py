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
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"username": "demo-investigator", "password": "<local demo password>"}
            ]
        }
    )

    username: Username
    password: str = Field(
        min_length=1, max_length=256, json_schema_extra={"writeOnly": True}
    )


class UserCreate(Login):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "username": "training-analyst",
                    "password": "<new strong local password>",
                    "role": "investigator",
                }
            ]
        }
    )

    password: str = Field(
        min_length=12, max_length=256, json_schema_extra={"writeOnly": True}
    )
    role: Literal["investigator", "administrator"] = "investigator"


class PasswordChange(Input):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "current_password": "<current password>",
                    "new_password": "<new local password>",
                }
            ]
        }
    )

    current_password: str = Field(
        min_length=1, max_length=256, json_schema_extra={"writeOnly": True}
    )
    new_password: str = Field(
        min_length=12, max_length=256, json_schema_extra={"writeOnly": True}
    )


class PasswordReset(Input):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "administrator_password": "<current administrator password>",
                    "temporary_password": "<temporary training password>",
                }
            ]
        }
    )

    administrator_password: str = Field(
        min_length=1, max_length=256, json_schema_extra={"writeOnly": True}
    )
    temporary_password: str = Field(
        min_length=12, max_length=256, json_schema_extra={"writeOnly": True}
    )


class AccountStatus(Input):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "administrator_password": "<current administrator password>",
                    "disabled": True,
                }
            ]
        }
    )

    administrator_password: str = Field(
        min_length=1, max_length=256, json_schema_extra={"writeOnly": True}
    )
    disabled: bool


class CaseInput(Input):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "title": "Synthetic Orchid review",
                    "investigator": "Training analyst",
                    "severity": "medium",
                    "status": "open",
                }
            ]
        }
    )

    title: Name
    description: str = Field(default="", max_length=20000)
    investigator: Name
    classification: Name = "Unclassified"
    severity: Severity = "medium"
    status: Status = "open"


class Note(Input):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "body": "Synthetic training record reviewed; compare with the original file."
                }
            ]
        }
    )

    body: Reason
    event_id: str | None = Field(default=None, max_length=64)


class RelationshipReview(Input):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "review": "pending",
                    "reason": "Awaiting corroboration in the synthetic fixture.",
                }
            ]
        }
    )

    review: Literal["confirmed", "rejected", "pending"]
    reason: Reason


class FindingReview(Input):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"stage": "observation", "reason": "Training case review in progress."}
            ]
        }
    )

    stage: Literal["observation", "suspicious", "confirmed", "dismissed"]
    reason: Reason
    override: int | None = Field(default=None, ge=0, le=100)


class CustodyAction(Input):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "recipient": "training-analyst",
                    "reason": "Synthetic training handoff.",
                }
            ]
        }
    )

    reason: Reason
    recipient: Username | None = None


class Analyze(Input):
    model_config = ConfigDict(json_schema_extra={"examples": [{"window": 300}]})

    window: int = Field(default=300, ge=1, le=86400)


class Rule(Input):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"enabled": True, "threshold": 5, "window": 300}]
        }
    )

    enabled: bool
    threshold: int = Field(ge=1, le=2**31 - 1)
    window: int = Field(ge=1, le=86400)


class Indicator(Input):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "kind": "domain",
                    "value": "example.invalid",
                    "source": "Training fixture",
                    "confidence": 50,
                }
            ]
        }
    )

    kind: Literal[
        "ip", "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "sha512"
    ]
    value: str = Field(min_length=1, max_length=4096)
    source: Name
    confidence: int = Field(default=50, ge=0, le=100)
    description: str = Field(default="", max_length=4000)
    expires_at: str | None = Field(default=None, max_length=64)
    tags: list[Name] = Field(default_factory=list, max_length=20)
