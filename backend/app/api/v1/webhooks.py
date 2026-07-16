"""Webhook routes: register outgoing webhooks + ingest incoming CI results."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_current_user
from app.models.ops import Webhook
from app.models.user import User
from app.schemas.common import ORMModel
from pydantic import BaseModel

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class WebhookCreate(BaseModel):
    project_id: uuid.UUID | None = None
    url: str
    events: list[str] = []


class WebhookRead(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID | None
    url: str
    events: list[str]
    is_active: bool


@router.post("", response_model=WebhookRead, status_code=status.HTTP_201_CREATED)
def create_webhook(payload: WebhookCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> Webhook:
    wh = Webhook(project_id=payload.project_id, url=payload.url, events=payload.events, is_active=True)
    db.add(wh)
    db.commit()
    db.refresh(wh)
    return wh


@router.get("", response_model=list[WebhookRead])
def list_webhooks(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[Webhook]:
    return list(db.scalars(select(Webhook)).all())
