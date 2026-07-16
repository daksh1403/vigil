"""Repository scan routes — a convenience layer over scans for repo targets."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.finding import Finding
from app.models.project import Project, Target, TargetKind
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.schemas.project import ProjectCreate, ProjectRead, TargetRead
from app.schemas.scan import ScanRead

router = APIRouter(prefix="/repositories", tags=["repositories"])


@router.post("/scan", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def scan_repository(
    repo_url: str,
    project_id: uuid.UUID | None = None,
    bg: BackgroundTasks = None,  # type: ignore
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Scan:
    # Get or create project for this repo
    if project_id:
        project = db.get(Project, project_id)
        if not project or project.owner_id != user.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    else:
        name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        project = Project(name=name, type="repo", owner_id=user.id)
        db.add(project)
        db.commit()
        db.refresh(project)

    target = Target(project_id=project.id, kind=TargetKind.repo, value=repo_url)
    db.add(target)
    db.commit()
    db.refresh(target)

    scan = Scan(
        project_id=project.id, target_id=target.id, scan_type="full",
        trigger="ui", initiated_by=user.id, status=ScanStatus.pending,
        config={"scanners": []},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from app.api.v1.scans import _enqueue_scan
    bg.add_task(_enqueue_scan, scan.id) if bg else _enqueue_scan(scan.id)
    return scan


@router.get("", response_model=list[ProjectRead])
def list_repositories(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[Project]:
    return list(db.scalars(
        select(Project).where(Project.owner_id == user.id, Project.type == "repo")
    ).all())


@router.get("/{project_id}/history", response_model=list[ScanRead])
def repo_history(project_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[Scan]:
    project = db.get(Project, project_id)
    if not project or project.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository not found")
    return list(db.scalars(
        select(Scan).where(Scan.project_id == project_id).order_by(Scan.created_at.desc())
    ).all())
