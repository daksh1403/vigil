"""Health + metrics routes."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.models.user import User
import app.core.metrics  # noqa: F401 — register custom metrics

router = APIRouter(tags=["health"])
_start = time.time()


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "app": settings.app_name, "env": settings.env, "uptime_sec": int(time.time() - _start)}


@router.get("/health/ready")
def ready(db: Session = Depends(get_db)) -> dict:
    try:
        db.execute(User.__table__.select().limit(1))
        return {"status": "ready", "database": "ok"}
    except Exception as e:  # pragma: no cover
        return Response(status_code=503, content=f'{{"status":"not ready","error":"{e}"}}', media_type="application/json")


if settings.prometheus_enabled:
    @router.get("/metrics")
    def metrics() -> Response:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
