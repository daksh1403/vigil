"""AI Triage schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import ORMModel


class AITriageRead(ORMModel):
    finding_id: uuid.UUID
    dedup_group_id: uuid.UUID | None
    fp_score: float | None
    fp_label: str | None
    risk_score: float | None
    mitre_tactics: list[str] | None
    mitre_techniques: list[str] | None
    owasp_id: str | None
    cwe_id: str | None
    explanation: str | None
    remediation: str | None
    llm_model: str | None
    prompt_version: str | None
    triage_method: str | None
    created_at: datetime | None


class DashboardStats(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    fp_rate: float
    by_scanner: dict[str, int]
    by_owasp: dict[str, int]
    recent_scans: list[dict]
    risk_trend: list[dict]
