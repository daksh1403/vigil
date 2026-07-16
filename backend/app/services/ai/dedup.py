"""Semantic dedup via pgvector cosine similarity.

Groups findings that are semantically the same vulnerability reported by
different scanners (e.g. Nuclei + ZAP + Semgrep all flag Log4Shell). Uses
cosine similarity over the finding embeddings stored in pgvector.
"""
from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models.finding import Finding

log = get_logger(__name__)


def find_duplicates(db: Session, finding: Finding, embedding: list[float]) -> uuid.UUID | None:
    """Return the id of a semantically-duplicate existing finding, if any.

    Uses pgvector cosine distance operator (<=>). Falls back to None if
    pgvector is unavailable or no embedding exists.
    """
    if not embedding:
        return None
    threshold = settings.dedup_similarity_threshold
    try:
        # cosine distance = 1 - cosine_similarity; similarity > threshold ⟺ distance < 1-threshold
        stmt = text("""
            SELECT id FROM findings
            WHERE project_id = :pid
              AND id <> :fid
              AND embedding IS NOT NULL
              AND 1 - (embedding <=> CAST(:emb AS vector)) > :thr
            ORDER BY embedding <=> CAST(:emb AS vector)
            LIMIT 1
        """)
        row = db.execute(stmt, {
            "pid": str(finding.project_id),
            "fid": str(finding.id),
            "emb": str(embedding),
            "thr": threshold,
        }).first()
        return uuid.UUID(row[0]) if row else None
    except Exception as e:  # pgvector not installed or query error
        log.warning("dedup.pgvector_unavailable", error=str(e))
        return None


def store_embedding(db: Session, finding_id: uuid.UUID, embedding: list[float]) -> None:
    """Persist the embedding for a finding."""
    try:
        db.execute(
            text("UPDATE findings SET embedding = CAST(:emb AS vector) WHERE id = :fid"),
            {"emb": str(embedding), "fid": str(finding_id)},
        )
    except Exception as e:  # pragma: no cover
        log.warning("dedup.store_failed", error=str(e))
