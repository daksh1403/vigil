"""Database initialization: pgvector extension + bootstrap superuser.

Called at startup and by `make migrate`.
"""
from __future__ import annotations

from app.core.config import settings
from app.core.db import SessionLocal, engine
from app.core.logging import get_logger
from app.core.security import hash_password
from app.models.user import User

log = get_logger(__name__)


def init_db() -> None:
    # Create pgvector extension if available
    from sqlalchemy import text

    with engine.begin() as conn:
        try:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            log.info("db.pgvector_enabled")
        except Exception as e:
            log.warning("db.pgvector_unavailable", error=str(e))

    # Create tables (idempotent; Alembic is the source of truth in prod)
    from app.core.db import Base
    import app.models  # noqa: F401 — register all models

    Base.metadata.create_all(bind=engine)

    # Bootstrap superuser
    with SessionLocal() as db:
        existing = db.query(User).filter(User.email == settings.first_superuser_email).first()
        if not existing:
            user = User(
                email=settings.first_superuser_email,
                password_hash=hash_password(settings.first_superuser_password),
                full_name="VIGIL Admin",
                role="admin",
                is_active=True,
                is_superuser=True,
            )
            db.add(user)
            db.commit()
            log.info("db.superuser_created", email=settings.first_superuser_email)


if __name__ == "__main__":
    init_db()
