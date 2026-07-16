"""Project / Target / AuthProfile schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, HttpUrl

from app.schemas.common import ORMModel


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None
    type: str = "both"


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class ProjectRead(ORMModel):
    id: uuid.UUID
    name: str
    description: str | None
    type: str
    owner_id: uuid.UUID
    created_at: datetime | None


class AuthProfileCreate(BaseModel):
    name: str
    kind: str = "none"
    secret: str | None = None  # plaintext; encrypted server-side
    notes: str | None = None


class AuthProfileRead(ORMModel):
    id: uuid.UUID
    name: str
    kind: str
    notes: str | None
    created_at: datetime | None


class TargetCreate(BaseModel):
    project_id: uuid.UUID
    kind: str = "url"
    value: str
    auth_profile_id: uuid.UUID | None = None


class TargetRead(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID
    kind: str
    value: str
    auth_profile_id: uuid.UUID | None
    created_at: datetime | None


class AssetCreate(BaseModel):
    project_id: uuid.UUID
    asset_type: str
    identifier: str
    criticality: int = 5


class AssetRead(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID
    asset_type: str
    identifier: str
    criticality: int
