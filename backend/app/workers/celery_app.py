"""Celery app + tasks.

Queues:
  - scans:   scan orchestration (runs scanner subprocesses)
  - triage:  AI triage (embeddings + LLM, CPU/latency heavy)
  - default: misc
"""
from __future__ import annotations

import uuid

from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "vigil",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    task_time_limit=settings.scanner_timeout + 120,
    task_soft_time_limit=settings.scanner_timeout,
    result_extended=True,
)


@celery_app.task(name="run_scan", queue="scans", bind=True)
def run_scan_task(self, scan_id: str) -> dict:
    from app.core.db import SessionLocal
    from app.workers.orchestrator import run_scan

    with SessionLocal() as db:
        run_scan(db, uuid.UUID(scan_id))
    # Chain into AI triage
    triage_scan_findings_task.apply_async(args=[scan_id], queue="triage")
    return {"scan_id": scan_id, "status": "completed"}


@celery_app.task(name="triage_scan_findings", queue="triage", bind=True)
def triage_scan_findings_task(self, scan_id: str) -> dict:
    from app.core.db import SessionLocal
    from app.services.ai.pipeline import triage_scan_findings

    with SessionLocal() as db:
        count = triage_scan_findings(db, uuid.UUID(scan_id))
    return {"scan_id": scan_id, "triaged": count}


@celery_app.task(name="triage_finding", queue="triage")
def triage_finding_task(finding_id: str) -> dict:
    from app.core.db import SessionLocal
    from app.models.finding import Finding
    from app.services.ai.pipeline import triage_finding

    with SessionLocal() as db:
        f = db.get(Finding, uuid.UUID(finding_id))
        if f:
            triage_finding(db, f)
            db.commit()
    return {"finding_id": finding_id, "status": "triaged"}
