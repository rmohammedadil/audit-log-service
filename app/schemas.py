"""Pydantic schemas defining the audit service's public data contract."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


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


class AuditEventRead(BaseModel):
    """API representation of a persisted audit event and its integrity data."""

    # SQLAlchemy exposes snake_case attributes; API responses emit aliases.
    model_config = ConfigDict(from_attributes=True, validate_by_name=True)

    id: int
    event_type: EventType = Field(alias="eventType")
    actor_id: ActorId = Field(alias="actorId")
    resource_type: ResourceType = Field(alias="resourceType")
    resource_id: ResourceId = Field(alias="resourceId")
    payload: dict[str, Any]
    timestamp: datetime
    previous_hash: str = Field(alias="previousHash")
    content_hash: str = Field(alias="contentHash")


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
