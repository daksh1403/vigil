"""Finding model (Unified Finding Schema) + FindingGroup + IgnoreRule + ScanDiff."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON, DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint, Uuid, func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

# pgvector is optional at import time (tests may run without the extension).
try:
    from pgvector.sqlalchemy import Vector  # type: ignore

    HAS_PGVECTOR = True
except Exception:  # pragma: no cover
    HAS_PGVECTOR = False

EMBED_DIM = 384  # all-MiniLM-L6-v2


class FindingCategory(str, enum.Enum):
    vuln = "vuln"
    secret = "secret"
    misconfig = "misconfig"
    sca = "sca"
    info = "info"


class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(str, enum.Enum):
    new = "new"
    confirmed = "confirmed"
    false_positive = "false_positive"
    fixed = "fixed"
    ignored = "ignored"


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("fingerprint", "project_id", name="uq_finding_fp_project"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("scans.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"))

    # Core identity
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[FindingCategory] = mapped_column(Enum(FindingCategory), default=FindingCategory.vuln)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.info)

    # Provenance
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_rule_id: Mapped[str | None] = mapped_column(String(255))
    scanner_confidence: Mapped[float | None] = mapped_column(Float)

    # Scoring / classification
    cvss: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    cwe: Mapped[str | None] = mapped_column(String(64))
    owasp_category: Mapped[str | None] = mapped_column(String(64))

    # Location
    target_ref: Mapped[str | None] = mapped_column(String(2048))
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_start: Mapped[int | None] = mapped_column(Integer)
    line_end: Mapped[int | None] = mapped_column(Integer)
    code_snippet: Mapped[str | None] = mapped_column(Text)
    http_request: Mapped[str | None] = mapped_column(Text)

    # Evidence + dedup
    evidence: Mapped[dict | None] = mapped_column(JSON)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    # Workflow
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.new)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Embedding for semantic dedup (nullable; populated by AI triage)
    if HAS_PGVECTOR:
        embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBED_DIM), nullable=True)
    else:  # pragma: no cover
        embedding: Mapped[list[float] | None] = mapped_column(JSON, nullable=True)  # type: ignore[no-redef]

    scan = relationship("Scan", back_populates="findings")
    ai_triage = relationship("AITriage", back_populates="finding", uselist=False, cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Finding {self.scanner}:{self.title} [{self.severity}]>"


class FindingGroup(Base):
    __tablename__ = "finding_groups"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    canonical_title: Mapped[str] = mapped_column(String(512), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)


class IgnoreRule(Base):
    __tablename__ = "ignore_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"))
    rule: Mapped[dict] = mapped_column(JSON, nullable=False)  # {scanner, rule_id, fingerprint, severity...}
    reason: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanDiff(Base):
    __tablename__ = "scan_diffs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("scans.id", ondelete="CASCADE"))
    baseline_scan_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("scans.id"))
    added: Mapped[int] = mapped_column(Integer, default=0)
    removed: Mapped[int] = mapped_column(Integer, default=0)
    changed: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
