"""Tests for the FP classifier heuristic + risk scoring."""
from __future__ import annotations

from app.services.ai.fp_classifier import classify
from app.services.ai.risk_score import compute_risk, exploitability_heuristic


class _FakeSev:
    def __init__(self, v):
        self.value = v


class _FakeFinding:
    def __init__(self, **kw):
        self.title = kw.get("title", "x")
        self.description = kw.get("description")
        self.scanner = kw.get("scanner", "nuclei")
        self.scanner_rule_id = kw.get("scanner_rule_id")
        self.scanner_confidence = kw.get("scanner_confidence", 0.8)
        self.cvss = kw.get("cvss")
        self.cwe = kw.get("cwe")
        self.owasp_category = kw.get("owasp")
        self.severity = _FakeSev(kw.get("severity", "high"))
        self.file_path = kw.get("file_path")
        self.target_ref = kw.get("target_ref")
        self.code_snippet = kw.get("code_snippet")
        self.evidence = kw.get("evidence")


def test_fp_classifier_high_confidence_tp():
    f = _FakeFinding(cvss=9.8, cwe="CWE-502", severity="critical", scanner_confidence=0.9)
    res = classify(f)
    assert res.label == "likely_tp"
    assert res.fp_score < 0.5


def test_fp_classifier_info_no_cwe_fp():
    f = _FakeFinding(cvss=None, cwe=None, severity="info", scanner_confidence=0.2)
    res = classify(f)
    assert res.fp_score > 0.4


def test_risk_score_bounds():
    f = _FakeFinding(cvss=10.0, severity="critical")
    r = compute_risk(f, fp_score=0.0, exploitability=0.9, asset_criticality=10)
    assert 0 <= r <= 10
    assert r > 5


def test_risk_score_fp_reduces():
    f = _FakeFinding(cvss=10.0, severity="critical")
    high = compute_risk(f, fp_score=0.0)
    low = compute_risk(f, fp_score=0.9)
    assert high > low
