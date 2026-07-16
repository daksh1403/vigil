"""Finding routes: list, detail, update status, re-triage."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.finding import Finding, FindingStatus
from app.models.project import Project
from app.models.user import User
from app.schemas.finding import FindingRead, FindingUpdate

router = APIRouter(prefix="/findings", tags=["findings"])


def _get_finding_or_404(scan_id: uuid.UUID, finding_id: uuid.UUID, db: Session, user: User) -> Finding:
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    project = db.get(Project, f.project_id)
    if not project or project.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return f


@router.get("", response_model=list[FindingRead])
def list_findings(
    scan_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    severity: str | None = None,
    scanner: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[Finding]:
    q = select(Finding).join(Project, Finding.project_id == Project.id).where(Project.owner_id == user.id)
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    if project_id:
        q = q.where(Finding.project_id == project_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if scanner:
        q = q.where(Finding.scanner == scanner)
    if status_filter:
        q = q.where(Finding.status == status_filter)
    if search:
        q = q.where(Finding.title.ilike(f"%{search}%"))
    return list(db.scalars(q.order_by(Finding.created_at.desc()).offset(offset).limit(limit)).all())


@router.get("/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Finding:
    return _get_finding_or_404(uuid.UUID(str(uuid.UUID(int=0))), finding_id, db, user)


@router.patch("/{finding_id}", response_model=FindingRead)
def update_finding(finding_id: uuid.UUID, payload: FindingUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Finding:
    f = _get_finding_or_404(uuid.UUID(str(uuid.UUID(int=0))), finding_id, db, user)
    if payload.status:
        try:
            f.status = FindingStatus(payload.status)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid status")
    db.commit()
    db.refresh(f)
    return f


@router.post("/{finding_id}/triage/re-run", status_code=status.HTTP_202_ACCEPTED)
def re_run_triage(finding_id: uuid.UUID, bg: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    f = _get_finding_or_404(uuid.UUID(str(uuid.UUID(int=0))), finding_id, db, user)

    def _run() -> None:
        try:
            from app.workers.celery_app import triage_finding_task
            triage_finding_task.apply_async(args=[str(f.id)], queue="triage")
        except Exception:
            from app.core.db import SessionLocal
            from app.services.ai.pipeline import triage_finding
            with SessionLocal() as s:
                triage_finding(s, s.get(Finding, f.id))
                s.commit()

    bg.add_task(_run)
    return {"finding_id": str(f.id), "status": "triage_queued"}
