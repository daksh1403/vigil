"""Project / target / asset routes."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.core.security import encrypt_secret, require_role
from app.models.project import Asset, AuthProfile, Project, Target
from app.models.user import User
from app.schemas.project import (
    AssetCreate, AssetRead, AuthProfileCreate, AuthProfileRead,
    ProjectCreate, ProjectRead, ProjectUpdate, TargetCreate, TargetRead,
)

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Project:
    project = Project(name=payload.name, description=payload.description, type=payload.type, owner_id=user.id)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("", response_model=list[ProjectRead])
def list_projects(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[Project]:
    return list(db.scalars(select(Project).where(Project.owner_id == user.id)).all())


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(project_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Project:
    p = db.get(Project, project_id)
    if not p or p.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return p


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_role("engineer"))) -> None:
    p = db.get(Project, project_id)
    if p:
        db.delete(p)
        db.commit()


# ── Targets ──────────────────────────────────────────────────
@router.post("/{project_id}/targets", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
def add_target(project_id: uuid.UUID, payload: TargetCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Target:
    p = db.get(Project, project_id)
    if not p or p.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    payload.project_id = project_id
    target = Target(project_id=project_id, kind=payload.kind, value=payload.value, auth_profile_id=payload.auth_profile_id)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/{project_id}/targets", response_model=list[TargetRead])
def list_targets(project_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[Target]:
    return list(db.scalars(select(Target).where(Target.project_id == project_id)).all())


# ── Auth profiles ────────────────────────────────────────────
@router.post("/auth-profiles", response_model=AuthProfileRead, status_code=status.HTTP_201_CREATED)
def create_auth_profile(payload: AuthProfileCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> AuthProfile:
    profile = AuthProfile(
        name=payload.name, kind=payload.kind, notes=payload.notes,
        secret_ref=encrypt_secret(payload.secret) if payload.secret else None,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


# ── Assets ────────────────────────────────────────────────────
@router.post("/{project_id}/assets", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def add_asset(project_id: uuid.UUID, payload: AssetCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Asset:
    payload.project_id = project_id
    asset = Asset(project_id=project_id, asset_type=payload.asset_type, identifier=payload.identifier, criticality=payload.criticality)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset
