"""Public V4-only event contracts; server evidence fields are never accepted."""
from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field
from app.schemas import AuditEventCreate

class V4AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, validate_by_name=True)
    event_ref: str = Field(alias="eventRef")
    event_type: str = Field(alias="eventType")
    actor_id: str = Field(alias="actorId")
    resource_type: str = Field(alias="resourceType")
    resource_id: str = Field(alias="resourceId")
    payload: dict[str, Any]
    timestamp: datetime
    previous_content_hash: str = Field(alias="previousContentHash")
    content_hash: str = Field(alias="contentHash")
    hash_scheme_version: str = Field(alias="hashSchemeVersion")
    previous_chain_hash: str = Field(alias="previousChainHash")
    chain_hash: str = Field(alias="chainHash")

V4AuditEventCreate = AuditEventCreate
