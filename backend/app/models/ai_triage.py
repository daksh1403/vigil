"""AITriage model — AI enrichment (1:1 with Finding)."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


class FPLabel(str, enum.Enum):
    likely_tp = "likely_tp"
    uncertain = "uncertain"
    likely_fp = "likely_fp"


class AITriage(Base):
    __tablename__ = "ai_triage"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    dedup_group_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("finding_groups.id"))
    fp_score: Mapped[float | None] = mapped_column(Float)  # 0..1 (1 = likely FP)
    fp_label: Mapped[FPLabel | None] = mapped_column(Enum(FPLabel))
    risk_score: Mapped[float | None] = mapped_column(Float)  # 0..10

    # Mappings
    mitre_tactics: Mapped[list[str] | None] = mapped_column(JSON)
    mitre_techniques: Mapped[list[str] | None] = mapped_column(JSON)
    owasp_id: Mapped[str | None] = mapped_column(String(32))
    cwe_id: Mapped[str | None] = mapped_column(String(32))

    # LLM output
    explanation: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)

    # Provenance
    llm_model: Mapped[str | None] = mapped_column(String(128))
    prompt_version: Mapped[str | None] = mapped_column(String(32))
    tokens_in: Mapped[int | None] = mapped_column(Integer)
    tokens_out: Mapped[int | None] = mapped_column(Integer)
    triage_method: Mapped[str | None] = mapped_column(String(32))  # llm|classical|fallback

    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    finding = relationship("Finding", back_populates="ai_triage")
