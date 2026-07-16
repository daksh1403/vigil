"""Scanner registry — maps scanner names to adapter classes and selects
applicable scanners for a given target kind."""
from __future__ import annotations

from app.workers.scanners.base import ScannerAdapter, ScanContext
from app.workers.scanners.bandit import BanditAdapter
from app.workers.scanners.gitleaks import GitleaksAdapter
from app.workers.scanners.recon import HttpxAdapter, KatanaAdapter
from app.workers.scanners.nuclei import NucleiAdapter
from app.workers.scanners.osvscanner import OSVScannerAdapter
from app.workers.scanners.pipaudit import PipAuditAdapter
from app.workers.scanners.semgrep import SemgrepAdapter
from app.workers.scanners.trivy import TrivyAdapter

REGISTRY: dict[str, type[ScannerAdapter]] = {
    "nuclei": NucleiAdapter,
    "katana": KatanaAdapter,
    "httpx": HttpxAdapter,
    "semgrep": SemgrepAdapter,
    "bandit": BanditAdapter,
    "trivy": TrivyAdapter,
    "gitleaks": GitleaksAdapter,
    "osv-scanner": OSVScannerAdapter,
    "pip-audit": PipAuditAdapter,
}


def get_adapter(name: str, ctx: ScanContext) -> ScannerAdapter:
    cls = REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown scanner: {name}. Available: {list(REGISTRY)}")
    return cls(ctx)


def applicable_scanners(target_kind: str, requested: list[str] | None = None) -> list[str]:
    """Return scanners that apply to a target kind (or the requested subset)."""
    names = requested if requested else list(REGISTRY)
    return [n for n in names if n in REGISTRY and target_kind in REGISTRY[n].supports_kinds]


def all_scanners() -> list[str]:
    return list(REGISTRY)
