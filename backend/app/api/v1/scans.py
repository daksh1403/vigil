"""Scan routes: create, list, detail, report, diff."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.finding import Finding
from app.models.project import Project, Target
from app.models.scan import Scan, ScanStatus, ScanTask
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanDetail, ScanRead, ScanTaskRead
from app.services.report import save_report

router = APIRouter(prefix="/scans", tags=["scans"])


def _enqueue_scan(scan_id: uuid.UUID) -> None:
    try:
        from app.workers.celery_app import run_scan_task
        run_scan_task.apply_async(args=[str(scan_id)], queue="scans")
    except Exception:
        # If no broker, run synchronously (dev convenience)
        from app.core.db import SessionLocal
        from app.workers.orchestrator import run_scan
        with SessionLocal() as db:
            run_scan(db, scan_id)


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(payload: ScanCreate, bg: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Scan:
    project = db.get(Project, payload.project_id)
    if not project or project.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    target = db.get(Target, payload.target_id)
    if not target or target.project_id != payload.project_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")

    scan = Scan(
        project_id=payload.project_id, target_id=payload.target_id,
        scan_type=payload.scan_type, trigger="ui", initiated_by=user.id,
        config={"scanners": payload.scanners, "profile": payload.profile},
        status=ScanStatus.pending,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    bg.add_task(_enqueue_scan, scan.id)
    return scan


@router.get("", response_model=list[ScanRead])
def list_scans(project_id: uuid.UUID | None = None, limit: int = 50, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[Scan]:
    q = select(Scan).join(Project, Scan.project_id == Project.id).where(Project.owner_id == user.id)
    if project_id:
        q = q.where(Scan.project_id == project_id)
    return list(db.scalars(q.order_by(Scan.created_at.desc()).limit(limit)).all())


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    project = db.get(Project, scan.project_id)
    if not project or project.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    tasks = list(db.scalars(select(ScanTask).where(ScanTask.scan_id == scan_id)).all())
    finding_count = db.scalar(select(Finding).where(Finding.scan_id == scan_id).with_only_columns(Finding.id).limit(1))  # type: ignore[arg-type]
    detail = ScanDetail.model_validate(scan)
    detail.tasks = [ScanTaskRead.model_validate(t) for t in tasks]
    detail.finding_count = db.query(Finding).filter(Finding.scan_id == scan_id).count()
    return detail


@router.post("/{scan_id}/report")
def generate_report(scan_id: uuid.UUID, fmt: str = "json", db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    path = save_report(db, scan_id, fmt)
    return {"scan_id": str(scan_id), "format": fmt, "path": path}
