"""Unified Finding Schema (UFS) — the normalized contract every scanner emits.

This is the heart of VIGIL: regardless of which tool produced a finding, it is
converted to this schema by the normalizer adapters. UFS enables cross-scanner
deduplication and a uniform UI/API.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class FindingLocation(BaseModel):
    type: str = "url"  # url|file|image|code
    target: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    param: str | None = None
    code_snippet: str | None = None


class UnifiedFinding(BaseModel):
    """The normalized finding produced by a ScannerAdapter.parse()."""

    scanner: str
    scanner_rule_id: str | None = None
    scanner_confidence: float | None = None
    category: str = "vuln"  # vuln|secret|misconfig|sca|info
    severity: str = "info"  # info|low|medium|high|critical
    title: str
    description: str | None = None
    cvss: float | None = None
    cvss_vector: str | None = None
    cwe: str | None = None
    owasp_category: str | None = None
    location: FindingLocation = Field(default_factory=FindingLocation)
    evidence: dict | None = None  # raw per-tool payload
    fingerprint: str | None = None  # stable hash; computed if absent


class FindingRead(ORMModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    project_id: uuid.UUID
    title: str
    description: str | None
    category: str
    severity: str
    scanner: str
    scanner_rule_id: str | None
    scanner_confidence: float | None
    cvss: float | None
    cvss_vector: str | None
    cwe: str | None
    owasp_category: str | None
    target_ref: str | None
    file_path: str | None
    line_start: int | None
    line_end: int | None
    code_snippet: str | None
    http_request: str | None
    evidence: dict | None
    fingerprint: str
    status: str
    created_at: datetime | None
    ai_triage: "AITriageRead | None" = None


class FindingUpdate(BaseModel):
    status: str | None = None  # confirmed|false_positive|fixed|ignored


class FindingListFilters(BaseModel):
    severity: str | None = None
    scanner: str | None = None
    category: str | None = None
    status: str | None = None
    search: str | None = None


from app.schemas.ai_triage import AITriageRead  # noqa: E402

FindingRead.model_rebuild()
