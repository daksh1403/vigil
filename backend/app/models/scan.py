"""Scan and ScanTask models."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, JSON, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ScanTrigger(str, enum.Enum):
    ui = "ui"
    api = "api"
    schedule = "schedule"
    ci = "ci"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("targets.id", ondelete="CASCADE"))
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.pending)
    scan_type: Mapped[str] = mapped_column(String(64), default="full")  # full|dast|sast|sca|secrets
    trigger: Mapped[ScanTrigger] = mapped_column(Enum(ScanTrigger), default=ScanTrigger.ui)
    config: Mapped[dict | None] = mapped_column(JSON)  # scanners[], profile, options
    initiated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    error: Mapped[str | None] = mapped_column(Text)
    progress: Mapped[int] = mapped_column(Integer, default=0)  # 0..100
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_sec: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), server_default=func.now())

    project = relationship("Project", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    tasks = relationship("ScanTask", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("scans.id", ondelete="CASCADE"))
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.pending)
    raw_output_ref: Mapped[str | None] = mapped_column(String(1024))  # path to raw JSONL/SARIF
    stdout_log_ref: Mapped[str | None] = mapped_column(String(1024))
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_sec: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="tasks")
