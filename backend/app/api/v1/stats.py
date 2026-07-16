"""Stats / dashboard routes."""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.ai_triage import AITriage
from app.models.finding import Finding, FindingStatus, Severity
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), user: User = Depends(get_current_user), limit: int = 10) -> dict:
    user_projects = select(Project.id).where(Project.owner_id == user.id)
    base = select(Finding).join(Scan, Finding.scan_id == Scan.id).where(Scan.project_id.in_(user_projects))

    sev_counts = dict(db.execute(
        select(Finding.severity, func.count()).where(Finding.project_id.in_(user_projects)).group_by(Finding.severity)
    ).all())

    total = sum(sev_counts.values())
    by_scanner = dict(db.execute(
        select(Finding.scanner, func.count()).where(Finding.project_id.in_(user_projects)).group_by(Finding.scanner)
    ).all())

    # FP rate from ai_triage
    triaged = db.scalar(select(func.count()).select_from(AITriage).join(Finding, AITriage.finding_id == Finding.id).where(Finding.project_id.in_(user_projects))) or 0
    fp_count = db.scalar(select(func.count()).select_from(AITriage).where(AITriage.fp_label == "likely_fp")) or 0
    fp_rate = (fp_count / triaged) if triaged else 0.0

    # OWASP distribution
    by_owasp = dict(db.execute(
        select(Finding.owasp_category, func.count()).where(Finding.project_id.in_(user_projects), Finding.owasp_category.isnot(None)).group_by(Finding.owasp_category)
    ).all())

    recent_scans = db.scalars(
        select(Scan).where(Scan.project_id.in_(user_projects)).order_by(Scan.created_at.desc()).limit(limit)
    ).all()

    return {
        "total_findings": total,
        "critical": sev_counts.get(Severity.critical, 0),
        "high": sev_counts.get(Severity.high, 0),
        "medium": sev_counts.get(Severity.medium, 0),
        "low": sev_counts.get(Severity.low, 0),
        "info": sev_counts.get(Severity.info, 0),
        "fp_rate": round(fp_rate, 3),
        "by_scanner": {k.value if hasattr(k, "value") else k: v for k, v in by_scanner.items()},
        "by_owasp": {k: v for k, v in by_owasp.items()},
        "recent_scans": [
            {"id": str(s.id), "status": s.status.value if hasattr(s.status, "value") else s.status,
             "progress": s.progress, "created_at": s.created_at.isoformat() if s.created_at else None}
            for s in recent_scans
        ],
        "risk_trend": [],
    }
