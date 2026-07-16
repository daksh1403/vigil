"""Project, Target, AuthProfile, Asset models."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, JSON, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


class ProjectType(str, enum.Enum):
    web = "web"
    repo = "repo"
    both = "both"


class TargetKind(str, enum.Enum):
    url = "url"
    repo = "repo"
    image = "image"


class AuthKind(str, enum.Enum):
    cookie = "cookie"
    header = "header"
    basic = "basic"
    oauth = "oauth"
    none = "none"


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    type: Mapped[ProjectType] = mapped_column(Enum(ProjectType), default=ProjectType.both)
    owner_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="projects")
    targets = relationship("Target", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan")


class AuthProfile(Base):
    __tablename__ = "auth_profiles"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[AuthKind] = mapped_column(Enum(AuthKind), default=AuthKind.none)
    # Encrypted payload (cookie/header value/token). See core.security.encrypt_secret.
    secret_ref: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    targets = relationship("Target", back_populates="auth_profile")


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"))
    kind: Mapped[TargetKind] = mapped_column(Enum(TargetKind), default=TargetKind.url)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    auth_profile_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("auth_profiles.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    project = relationship("Project", back_populates="targets")
    auth_profile = relationship("AuthProfile", back_populates="targets")
    scans = relationship("Scan", back_populates="target")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"))
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    identifier: Mapped[str] = mapped_column(String(512), nullable=False)
    criticality: Mapped[int] = mapped_column(Integer, default=5)  # 1..10
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    project = relationship("Project", back_populates="assets")
