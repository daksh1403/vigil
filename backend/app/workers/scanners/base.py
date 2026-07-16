"""ScannerAdapter base class.

Every scanner is wrapped behind a common interface so the orchestrator and UI
treat them uniformly. An adapter:
  1. builds the CLI invocation for a target,
  2. runs it as a subprocess (capturing stdout/stderr + raw output file),
  3. parses the tool's native output into a list of UnifiedFinding (UFS).

Adapters never touch the database directly — they return UFS dicts; the
normalizer persists them. This keeps scanners pure and testable.
"""
from __future__ import annotations

import abc
import hashlib
import json
import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.finding import FindingLocation, UnifiedFinding

log = get_logger(__name__)


@dataclass
class ScanContext:
    """Context passed to every adapter for a single scan."""

    target_value: str  # URL or repo path
    target_kind: str  # url|repo|image
    workdir: str  # temp working dir for this scan
    scanners_config: dict[str, Any] = field(default_factory=dict)
    auth: dict[str, str] | None = None  # headers/cookies for authenticated scans


@dataclass
class ScannerResult:
    scanner: str
    findings: list[UnifiedFinding]
    raw_output_ref: str | None
    stdout: str
    stderr: str
    returncode: int
    duration_sec: float
    error: str | None = None


class ScannerAdapter(abc.ABC):
    """Abstract base for all scanner adapters."""

    name: str = "base"
    supports_kinds: tuple[str, ...] = ("url", "repo", "image")
    category: str = "vuln"
    binary: str = ""
    default_args: list[str] = []

    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx

    # ── public API ─────────────────────────────────────────────
    def run(self) -> ScannerResult:
        """Execute the scanner and return parsed findings."""
        if self.ctx.target_kind not in self.supports_kinds:
            return ScannerResult(
                scanner=self.name,
                findings=[],
                raw_output_ref=None,
                stdout="",
                stderr=f"scanner {self.name} does not support target kind {self.ctx.target_kind}",
                returncode=0,
                duration_sec=0.0,
                error="unsupported target kind",
            )

        os.makedirs(self.ctx.workdir, exist_ok=True)
        raw_path = os.path.join(self.ctx.workdir, f"{self.name}.json")
        cmd = self.build_command(raw_path)
        log.info("scanner.run", scanner=self.name, target=self.ctx.target_value, cmd=cmd)

        started = datetime.now(timezone.utc)
        try:
            proc = subprocess.run(  # noqa: S603 — command built internally
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.scanner_timeout,
                cwd=self.ctx.workdir,
                check=False,
            )
            returncode = proc.returncode
            stdout, stderr = proc.stdout, proc.stderr
            error = None
        except subprocess.TimeoutExpired as e:
            returncode = 124
            stdout, stderr = (e.stdout or ""), (e.stderr or "")
            error = f"timeout after {settings.scanner_timeout}s"
        except FileNotFoundError:
            returncode = 127
            stdout, stderr = "", f"{self.binary} not found in PATH"
            error = stderr
        except Exception as e:  # pragma: no cover
            returncode = 1
            stdout, stderr = "", str(e)
            error = str(e)

        duration = (datetime.now(timezone.utc) - started).total_seconds()
        findings: list[UnifiedFinding] = []
        if returncode in (0, 1) and os.path.exists(raw_path):  # 1 = findings found (some tools)
            try:
                findings = self.parse(raw_path)
            except Exception as e:  # pragma: no cover
                log.error("scanner.parse_failed", scanner=self.name, error=str(e))
                error = f"parse failed: {e}"

        log.info(
            "scanner.done",
            scanner=self.name,
            findings=len(findings),
            returncode=returncode,
            duration=duration,
        )
        return ScannerResult(
            scanner=self.name,
            findings=findings,
            raw_output_ref=raw_path if os.path.exists(raw_path) else None,
            stdout=stdout[:20000],
            stderr=stderr[:20000],
            returncode=returncode,
            duration_sec=duration,
            error=error,
        )

    # ── to be implemented by subclasses ───────────────────────
    @abc.abstractmethod
    def build_command(self, raw_output_path: str) -> list[str]:
        """Return the CLI argv list. Write native output to raw_output_path."""

    @abc.abstractmethod
    def parse(self, raw_output_path: str) -> list[UnifiedFinding]:
        """Parse native output file → list of UnifiedFinding."""

    # ── helpers ───────────────────────────────────────────────
    @staticmethod
    def compute_fingerprint(*parts: str) -> str:
        """Stable hash for dedup/ignore. Order-independent join."""
        joined = "|".join(p for p in parts if p)
        return "sha256:" + hashlib.sha256(joined.encode()).hexdigest()[:32]

    @staticmethod
    def severity_from_string(s: str | None) -> str:
        if not s:
            return "info"
        s = s.strip().lower()
        m = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium",
             "low": "low", "info": "info", "informational": "info", "none": "info", "unknown": "info"}
        return m.get(s, "info")

    def _write_input(self, lines: list[str], name: str = "input.txt") -> str:
        path = os.path.join(self.ctx.workdir, name)
        with open(path, "w") as f:
            f.write("\n".join(lines))
        return path

    def _cmd_str(self, cmd: list[str]) -> str:
        return " ".join(shlex.quote(c) for c in cmd)
