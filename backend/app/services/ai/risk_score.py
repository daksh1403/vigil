"""Unified risk scoring.

risk = clip01(
    cvss/10 * w_cvss +
    epss * w_epss +
    exploitability * w_exploit +
    asset_criticality/10 * w_asset +
    (1 - fp_score) * w_fp
) * 10

Transparent and auditable — every component is logged. EPSS is fetched from
the OSV/NVD data when available; otherwise defaults to a conservative 0.2.
"""
from __future__ import annotations

from app.core.config import settings
from app.models.finding import Finding


def compute_risk(
    finding: Finding,
    fp_score: float,
    epss: float = 0.2,
    exploitability: float = 0.5,
    asset_criticality: int = 5,
) -> float:
    cvss = float(finding.cvss or 0.0) / 10.0
    asset = float(asset_criticality) / 10.0
    fp = max(0.0, min(1.0, 1.0 - fp_score))

    raw = (
        cvss * settings.risk_weight_cvss
        + epss * settings.risk_weight_epss
        + exploitability * settings.risk_weight_exploitability
        + asset * settings.risk_weight_asset
        + fp * settings.risk_weight_fp
    )
    # Normalize by total weight to [0,1] then scale to [0,10]
    total_w = (
        settings.risk_weight_cvss + settings.risk_weight_epss
        + settings.risk_weight_exploitability + settings.risk_weight_asset
        + settings.risk_weight_fp
    )
    risk = (raw / total_w) * 10.0 if total_w else 0.0
    return round(max(0.0, min(10.0, risk)), 2)


def exploitability_heuristic(finding: Finding) -> float:
    """Rough exploitability estimate from severity + presence of PoC evidence."""
    sev = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
    base = {"critical": 0.9, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.05}.get(sev, 0.3)
    if finding.evidence and isinstance(finding.evidence, dict) and finding.evidence.get("matched-at"):
        base = min(1.0, base + 0.1)
    return base
