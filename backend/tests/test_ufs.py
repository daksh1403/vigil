"""Tests for the Unified Finding Schema + normalizer fingerprinting."""
from __future__ import annotations

from app.schemas.finding import FindingLocation, UnifiedFinding
from app.workers.scanners.base import ScannerAdapter


def test_ufs_construction():
    f = UnifiedFinding(
        scanner="nuclei", scanner_rule_id="CVE-2021-44228",
        category="vuln", severity="critical", title="Log4Shell",
        description="RCE via JNDI", cvss=10.0, cwe="CWE-502",
        location=FindingLocation(type="url", target="https://app/api"),
        evidence={"matched-at": "https://app/api"},
    )
    assert f.severity == "critical"
    assert f.location.target == "https://app/api"
    assert f.fingerprint is None


def test_fingerprint_stable():
    fp1 = ScannerAdapter.compute_fingerprint("nuclei", "CVE-2021-44228", "https://app/api", "")
    fp2 = ScannerAdapter.compute_fingerprint("nuclei", "CVE-2021-44228", "https://app/api", "")
    assert fp1 == fp2
    assert fp1.startswith("sha256:")


def test_fingerprint_differs_on_target():
    fp1 = ScannerAdapter.compute_fingerprint("nuclei", "x", "https://a", "")
    fp2 = ScannerAdapter.compute_fingerprint("nuclei", "x", "https://b", "")
    assert fp1 != fp2


def test_severity_from_string():
    a = ScannerAdapter(  # type: ignore[abstract]
        ctx=None  # type: ignore[arg-type]
    ) if False else None
    assert ScannerAdapter.severity_from_string("CRITICAL") == "critical"
    assert ScannerAdapter.severity_from_string("Moderate") == "medium"
    assert ScannerAdapter.severity_from_string(None) == "info"
    assert ScannerAdapter.severity_from_string("unknown") == "info"
