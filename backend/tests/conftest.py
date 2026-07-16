"""Pytest fixtures."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def pytest_configure(config):  # noqa: D401
    # Use SQLite for tests (pgvector columns fall back to JSONB via the guard)
    os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
    os.environ.setdefault("SECRET_KEY", "test-secret")
    os.environ.setdefault("LLM_ENABLED", "false")
    os.environ.setdefault("PROMETHEUS_ENABLED", "false")
