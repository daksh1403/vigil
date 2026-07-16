"""Scan schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class ScanCreate(BaseModel):
    project_id: uuid.UUID
    target_id: uuid.UUID
    scan_type: str = "full"
    scanners: list[str] = Field(default_factory=list)  # empty = all applicable
    profile: dict | None = None


class ScanTaskRead(ORMModel):
    id: uuid.UUID
    scanner: str
    status: str
    finding_count: int
    duration_sec: int | None
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None


class ScanRead(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID
    status: str
    scan_type: str
    trigger: str
    progress: int
    finding_count: int = 0
    duration_sec: int | None = None
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime | None


class ScanDetail(ScanRead):
    tasks: list[ScanTaskRead] = []


class ScanDiffRead(BaseModel):
    added: int
    removed: int
    changed: int
    new_findings: list[dict] = []
