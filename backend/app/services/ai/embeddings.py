"""Embedding service for semantic finding dedup.

Uses sentence-transformers (all-MiniLM-L6-v2, 384-dim) — small, CPU-friendly,
runs on a MacBook without a GPU. The model is lazily loaded and cached.
"""
from __future__ import annotations

import threading
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

_MODEL_NAME = "all-MiniLM-L6-v2"
_model_lock = threading.Lock()
_model: Any | None = None


def _get_model() -> Any:
    global _model
    if _model is not None:
        return _model
    with _model_lock:
        if _model is not None:
            return _model
        try:
            from sentence_transformers import SentenceTransformer

            _model = SentenceTransformer(_MODEL_NAME)
            log.info("embeddings.model_loaded", model=_MODEL_NAME)
        except Exception as e:  # pragma: no cover
            log.warning("embeddings.model_unavailable", error=str(e))
            _model = None
    return _model


def embed_text(text: str) -> list[float] | None:
    """Embed a single string. Returns None if the model is unavailable."""
    model = _get_model()
    if model is None or not text:
        return None
    try:
        vec = model.encode(text, normalize_embeddings=True, show_progress_bar=False)
        return vec.tolist()
    except Exception as e:  # pragma: no cover
        log.error("embeddings.encode_failed", error=str(e))
        return None


def embed_finding(title: str, description: str | None, scanner: str, cwe: str | None) -> list[float] | None:
    """Build a canonical text representation of a finding for embedding."""
    parts = [scanner, title]
    if description:
        parts.append(description[:500])
    if cwe:
        parts.append(cwe)
    return embed_text(" | ".join(parts))
