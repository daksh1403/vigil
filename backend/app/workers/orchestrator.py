"""Scan orchestrator — runs adapters, persists findings, kicks off AI triage.

Runs inside a Celery worker. Each scan:
  1. selects applicable scanners for the target kind,
  2. runs each adapter as a subprocess (capturing native output),
  3. normalizes findings into the DB,
  4. enqueues AI triage for the batch.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.db import SessionLocal
from app.core.logging import get_logger
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus, ScanTask
from app.models.project import Target
from app.services.normalizer import persist_findings
from app.workers.scanners import ScanContext, applicable_scanners, get_adapter

log = get_logger(__name__)


def run_scan(db: Session, scan_id: uuid.UUID) -> None:
    scan = db.get(Scan, scan_id)
    if not scan:
        log.error("orchestrator.scan_not_found", scan_id=str(scan_id))
        return

    target = db.get(Target, scan.target_id)
    if not target:
        _fail(db, scan, "target not found")
        return

    scan.status = ScanStatus.running
    scan.started_at = datetime.now(timezone.utc)
    db.commit()

    config = scan.config or {}
    requested = config.get("scanners") or []
    scanners = applicable_scanners(target.kind, requested or None)
    log.info("orchestrator.start", scan_id=str(scan_id), target=target.value, scanners=scanners)

    workdir = tempfile.mkdtemp(prefix=f"vigil_scan_{scan_id}_")
    total_findings = 0

    # For repo targets, clone into the workdir so file-based scanners
    # (semgrep, bandit, gitleaks, trivy) operate on a local checkout.
    scan_target_value = target.value
    target_kind_val = target.kind.value if hasattr(target.kind, "value") else target.kind
    if target_kind_val == "repo" and target.value.startswith(("http://", "https://", "git@", "ssh://")):
        clone_dir = os.path.join(workdir, "repo")
        log.info("orchestrator.cloning", scan_id=str(scan_id), repo=target.value)
        clone_proc = subprocess.run(  # noqa: S603
            ["git", "clone", "--depth", "1", target.value, clone_dir],
            capture_output=True, text=True, timeout=300, check=False,
        )
        if clone_proc.returncode == 0 and os.path.isdir(clone_dir):
            scan_target_value = clone_dir
        else:
            log.warning("orchestrator.clone_failed", stderr=clone_proc.stderr[:500])


    for idx, name in enumerate(scanners, 1):
        task = ScanTask(scan_id=scan.id, scanner=name, status=ScanStatus.running,
                        started_at=datetime.now(timezone.utc))
        db.add(task)
        db.commit()

        ctx = ScanContext(
            target_value=scan_target_value,
            target_kind=target_kind_val,
            workdir=workdir,
            scanners_config=config.get("options", {}),
            auth=None,
        )
        try:
            result = get_adapter(name, ctx).run()
            inserted = persist_findings(db, scan.id, scan.project_id, result.findings)
            task.status = ScanStatus.completed
            task.finding_count = inserted
            task.raw_output_ref = result.raw_output_ref
            task.duration_sec = int(result.duration_sec)
            task.error = result.error
            total_findings += inserted
        except Exception as e:
            log.error("orchestrator.scanner_failed", scanner=name, error=str(e))
            task.status = ScanStatus.failed
            task.error = str(e)
            db.rollback()
            db.add(task)
        finally:
            task.finished_at = datetime.now(timezone.utc)
            db.commit()
            scan.progress = int(idx / len(scanners) * 100)
            db.commit()

    scan.status = ScanStatus.completed
    scan.progress = 100
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    log.info("orchestrator.complete", scan_id=str(scan_id), findings=total_findings)
    try:
        from app.core.metrics import scans_total
        scans_total.labels(status="completed").inc()
    except Exception:
        pass


def _fail(db: Session, scan: Scan, msg: str) -> None:
    scan.status = ScanStatus.failed
    scan.error = msg
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
