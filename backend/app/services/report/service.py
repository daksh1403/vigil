"""Report service — SARIF / HTML / JSON export."""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

from jinja2 import Template
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.finding import Finding, Severity
from app.models.scan import Scan

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SARIF_LEVEL = {"info": "note", "low": "warning", "medium": "warning", "high": "error", "critical": "error"}


def _findings_for_scan(db: Session, scan_id: uuid.UUID) -> list[Finding]:
    return sorted(
        db.query(Finding).filter(Finding.scan_id == scan_id).all(),
        key=lambda f: SEVERITY_RANK.get(f.severity.value if hasattr(f.severity, "value") else f.severity, 0),
        reverse=True,
    )


def to_sarif(db: Session, scan_id: uuid.UUID) -> dict:
    scan = db.get(Scan, scan_id)
    findings = _findings_for_scan(db, scan_id)
    results = []
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        results.append({
            "ruleId": f.scanner_rule_id or f.scanner,
            "level": SARIF_LEVEL.get(sev, "note"),
            "message": {"text": f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path or f.target_ref or ""},
                    "region": {"startLine": f.line_start or 1},
                }
            }],
            "partialFingerprints": {"primaryLocationLineHash": f.fingerprint},
        })
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "VIGIL", "version": "0.1.0", "informationUri": "https://github.com/daksh/vigil"}},
            "results": results,
            "invocations": [{
                "startTimeUtc": scan.started_at.isoformat() if scan and scan.started_at else None,
                "endTimeUtc": scan.finished_at.isoformat() if scan and scan.finished_at else None,
            }],
        }],
    }


def to_json(db: Session, scan_id: uuid.UUID) -> dict:
    findings = _findings_for_scan(db, scan_id)
    return {
        "scan_id": str(scan_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(findings),
        "findings": [_finding_to_dict(f) for f in findings],
    }


_HTML_TPL = """<!doctype html>
<html><head><meta charset="utf-8"><title>VIGIL Scan Report {{ scan_id }}</title>
<style>
body{font-family:-apple-system,system-ui,sans-serif;background:#0b0f17;color:#e5e7eb;margin:0;padding:24px}
h1{color:#fff;border-bottom:1px solid #1f2937;padding-bottom:8px}
.f{background:#111827;border:1px solid #1f2937;border-radius:8px;padding:14px;margin:12px 0}
.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}
.crit{background:#7f1d1d;color:#fecaca}.high{background:#92400e;color:#fde68a}
.med{background:#1e3a8a;color:#bfdbfe}.low{background:#374151;color:#d1d5db}.info{background:#1f2937;color:#9ca3af}
.meta{color:#9ca3af;font-size:12px;margin-top:6px}
</style></head><body>
<h1>VIGIL Security Report</h1>
<p>Scan {{ scan_id }} · {{ count }} findings · {{ generated }}</p>
{% for f in findings %}
<div class="f">
  <strong>{{ f.title }}</strong>
  <span class="sev {{ f.sev_class }}">{{ f.severity|upper }}</span>
  <div class="meta">{{ f.scanner }}{% if f.scanner_rule_id %} · {{ f.scanner_rule_id }}{% endif %}
  {% if f.cwe %} · {{ f.cwe }}{% endif %} · {{ f.location }}</div>
  {% if f.description %}<p>{{ f.description[:500] }}</p>{% endif %}
  {% if f.ai_explanation %}<p><em>AI:</em> {{ f.ai_explanation[:600] }}</p>{% endif %}
  {% if f.ai_remediation %}<p><em>Fix:</em> {{ f.ai_remediation[:600] }}</p>{% endif %}
</div>
{% endfor %}
</body></html>"""


def to_html(db: Session, scan_id: uuid.UUID) -> str:
    findings = _findings_for_scan(db, scan_id)
    sev_class = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "info"}
    rows = []
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        rows.append({
            "title": f.title, "severity": sev, "sev_class": sev_class.get(sev, "info"),
            "scanner": f.scanner, "scanner_rule_id": f.scanner_rule_id, "cwe": f.cwe,
            "description": f.description,
            "location": f.file_path or f.target_ref or "-",
            "ai_explanation": f.ai_triage.explanation if f.ai_triage else None,
            "ai_remediation": f.ai_triage.remediation if f.ai_triage else None,
        })
    return Template(_HTML_TPL).render(
        scan_id=str(scan_id), findings=rows, count=len(rows),
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def _finding_to_dict(f: Finding) -> dict:
    sev = f.severity.value if hasattr(f.severity, "value") else f.severity
    d = {
        "id": str(f.id), "title": f.title, "severity": sev, "scanner": f.scanner,
        "scanner_rule_id": f.scanner_rule_id, "cvss": f.cvss, "cwe": f.cwe,
        "owasp": f.owasp_category, "file": f.file_path, "target": f.target_ref,
        "line": f.line_start, "status": f.status.value if hasattr(f.status, "value") else f.status,
    }
    if f.ai_triage:
        d["ai"] = {
            "fp_score": f.ai_triage.fp_score, "risk_score": f.ai_triage.risk_score,
            "explanation": f.ai_triage.explanation, "remediation": f.ai_triage.remediation,
            "mitre_tactics": f.ai_triage.mitre_tactics, "mitre_techniques": f.ai_triage.mitre_techniques,
        }
    return d


def save_report(db: Session, scan_id: uuid.UUID, fmt: str) -> str:
    """Generate + persist a report. Returns the storage path."""
    os.makedirs("/data/reports", exist_ok=True)
    ext = {"sarif": "sarif", "json": "json", "html": "html"}.get(fmt, "json")
    path = f"/data/reports/{scan_id}.{ext}"
    if fmt == "sarif":
        content = json.dumps(to_sarif(db, scan_id), indent=2)
    elif fmt == "html":
        content = to_html(db, scan_id)
    else:
        content = json.dumps(to_json(db, scan_id), indent=2)
    with open(path, "w") as fobj:
        fobj.write(content)
    return path
