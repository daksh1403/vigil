"""Common schemas: pagination, timestamps."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class TimestampMixin(BaseModel):
    created_at: datetime | None = None
    updated_at: datetime | None = None


class Page(BaseModel):
    items: list
    total: int
    page: int
    size: int
    pages: int


class IDModel(BaseModel):
    id: uuid.UUID
