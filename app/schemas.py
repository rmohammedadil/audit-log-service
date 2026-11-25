"""Pydantic schemas defining the audit service's public data contract."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from app.services.audit_service import (
    ACCESS_OUTCOMES,
    ACCESS_OPERATIONS,
    ACCESS_RESOURCE_TYPE,
    CLIENT_ACCOUNT_ACCESS,
    RESERVED_LIFECYCLE_EVENT_TYPES,
    is_canonical_access_payload,
)


# These limits intentionally mirror the persisted column limits in AuditEvent.
EventType = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
ActorId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]
ResourceType = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
ResourceId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]


class AuditEventCreate(BaseModel):
    """Client-supplied fields for one new audit event.

    Python uses snake_case internally, while aliases preserve the camelCase
    API contract. Extra fields are forbidden so callers cannot choose values
    that the service must own, such as timestamps and hash-chain evidence.
    """

    model_config = ConfigDict(extra="forbid")

    event_type: EventType = Field(alias="eventType")
    actor_id: ActorId = Field(alias="actorId")
    resource_type: ResourceType = Field(alias="resourceType")
    resource_id: ResourceId = Field(alias="resourceId")
    payload: dict[str, Any]

    @field_validator("event_type")
    @classmethod
    def reject_reserved_lifecycle_event_type(cls, value: str) -> str:
        """Keep internal lifecycle evidence out of ordinary client input."""

        if value in RESERVED_LIFECYCLE_EVENT_TYPES:
            raise ValueError("eventType is reserved for internal lifecycle operations")
        return value

    @model_validator(mode="after")
    def require_canonical_access_contract(self) -> "AuditEventCreate":
        """Make access reports depend on explicit, rather than inferred, data."""

        if self.event_type == CLIENT_ACCOUNT_ACCESS:
            if self.resource_type != ACCESS_RESOURCE_TYPE:
                raise ValueError("client-account access events require resourceType customer_account")
            if not is_canonical_access_payload(self.payload):
                raise ValueError("access payload must contain only valid operation and outcome")
        return self


class AuditEventRead(BaseModel):
    """API representation of a persisted audit event and its integrity data."""

    # SQLAlchemy exposes snake_case attributes; API responses emit aliases.
    model_config = ConfigDict(from_attributes=True, validate_by_name=True)

    id: int
    # Persisted evidence must be serialized exactly as stored; request-only
    # normalization would hide direct database tampering from API consumers.
    event_type: str = Field(alias="eventType")
    actor_id: str = Field(alias="actorId")
    resource_type: str = Field(alias="resourceType")
    resource_id: str = Field(alias="resourceId")
    payload: dict[str, Any]
    timestamp: datetime
    previous_hash: str = Field(alias="previousHash")
    content_hash: str = Field(alias="contentHash")
    hash_scheme_version: str = Field(alias="hashSchemeVersion")
    previous_chain_hash: str = Field(alias="previousChainHash")
    chain_hash: str = Field(alias="chainHash")


class AuditEventQueryRead(AuditEventRead):
    """Retrieval view: hashes describe original evidence, payload may be masked."""

    redacted_paths: list[str] = Field(default_factory=list, alias="redactedPaths")


class AuditAccessReportRead(AuditEventQueryRead):
    """Read-only regulator-report representation of an explicit access event."""

    operation: str
    outcome: str


class RedactionRequest(BaseModel):
    """Trusted-local redaction request with non-sensitive reason codes only."""

    model_config = ConfigDict(extra="forbid")

    paths: list[str] = Field(min_length=1, max_length=50)
    reason: str


class RedactionRead(BaseModel):
    model_config = ConfigDict(validate_by_name=True)

    target_event_id: int = Field(alias="targetEventId")
    newly_redacted_path_count: int = Field(alias="newlyRedactedPathCount")
    newly_redacted_paths: list[str] = Field(alias="newlyRedactedPaths")
    action_event_id: int | None = Field(alias="actionEventId")


class AuditChainVerificationRead(BaseModel):
    """Public representation of a completed chain-verification result.

    This schema exposes verification metadata, not persisted event evidence.
    It intentionally leaves the verifier's safe explanatory detail unchanged
    while aliases keep the HTTP contract consistently camelCase.
    """

    model_config = ConfigDict(from_attributes=True, validate_by_name=True)

    is_intact: bool = Field(alias="isIntact")
    checked_record_count: int = Field(alias="checkedRecordCount")
    first_inconsistency_id: int | None = Field(alias="firstInconsistencyId")
    violation_type: str | None = Field(alias="violationType")
    detail: str


class ApiErrorRead(BaseModel):
    """Sanitized error body returned by documented API failure responses."""

    detail: str


class RetentionRunRead(BaseModel):
    """Public outcome of a server-configured logical archival run."""

    model_config = ConfigDict(validate_by_name=True)

    retention_days: int = Field(alias="retentionDays")
    cutoff: datetime
    archived_event_count: int = Field(alias="archivedEventCount")
    archived_event_ids: list[int] = Field(alias="archivedEventIds")
    action_event_id: int | None = Field(alias="actionEventId")


class RetentionRunRequest(BaseModel):
    """Deliberately empty body: policy and cutoff remain server-controlled."""

    model_config = ConfigDict(extra="forbid")


class AuditExportRequest(BaseModel):
    """One deliberately narrow selector for a self-contained export bundle."""

    model_config = ConfigDict(extra="forbid")

    actor_id: ActorId | None = Field(default=None, alias="actorId")
    resource_id: ResourceId | None = Field(default=None, alias="resourceId")
    include_archived: bool = Field(default=False, alias="includeArchived")

    @model_validator(mode="after")
    def require_exactly_one_selector(self) -> "AuditExportRequest":
        """Reject ambiguous or unbounded exports before any database access."""

        if (self.actor_id is None) == (self.resource_id is None):
            raise ValueError("exactly one of actorId or resourceId is required")
        return self
