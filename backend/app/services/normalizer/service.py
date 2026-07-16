"""Normalizer: persists UnifiedFinding (UFS) objects into the findings table.

Computes fingerprints, applies ignore rules, and upserts findings so re-scans
don't create duplicates. Also maintains FindingGroup history.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.finding import Finding, FindingGroup, FindingStatus, IgnoreRule, Severity
from app.schemas.finding import UnifiedFinding

log = get_logger(__name__)

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_severity(s: str) -> Severity:
    try:
        return Severity(s)
    except ValueError:
        return Severity.info


def persist_findings(
    db: Session,
    scan_id: uuid.UUID,
    project_id: uuid.UUID,
    ufs_findings: list[UnifiedFinding],
) -> int:
    """Persist a batch of UFS findings for a scan. Returns count inserted."""
    if not ufs_findings:
        return 0

    # Load ignore rules for this project (and global)
    ignore_rows = db.execute(
        select(IgnoreRule).where(
            (IgnoreRule.project_id == project_id) | (IgnoreRule.project_id.is_(None))
        )
    ).scalars().all()

    inserted = 0
    for uf in ufs_findings:
        fp = uf.fingerprint or _compute_fp(uf)
        if _is_ignored(uf, fp, ignore_rows):
            continue

        # Upsert by (fingerprint, project_id) — re-scan updates severity/evidence
        existing = db.execute(
            select(Finding).where(Finding.fingerprint == fp, Finding.project_id == project_id)
        ).scalar_one_or_none()

        if existing:
            # Update mutable fields, keep status unless it was fixed
            existing.severity = _max_severity(existing.severity, normalize_severity(uf.severity))
            existing.cvss = uf.cvss or existing.cvss
            existing.evidence = uf.evidence
            existing.scan_id = scan_id
            _upsert_group(db, project_id, fp, uf.title)
            continue

        finding = Finding(
            scan_id=scan_id,
            project_id=project_id,
            title=uf.title[:512],
            description=uf.description,
            category=uf.scanner,  # placeholder, set below
            severity=normalize_severity(uf.severity),
            scanner=uf.scanner,
            scanner_rule_id=uf.scanner_rule_id,
            scanner_confidence=uf.scanner_confidence,
            cvss=uf.cvss,
            cvss_vector=uf.cvss_vector,
            cwe=uf.cwe,
            owasp_category=uf.owasp_category,
            target_ref=uf.location.target,
            file_path=uf.location.file_path,
            line_start=uf.location.line_start,
            line_end=uf.location.line_end,
            code_snippet=uf.location.code_snippet,
            evidence=uf.evidence,
            fingerprint=fp,
            status=FindingStatus.new,
        )
        # category enum
        from app.models.finding import FindingCategory
        try:
            finding.category = FindingCategory(uf.category)
        except ValueError:
            finding.category = FindingCategory.vuln
        db.add(finding)
        _upsert_group(db, project_id, fp, uf.title)
        inserted += 1

    db.flush()
    log.info("normalizer.persisted", scan_id=str(scan_id), inserted=inserted, total=len(ufs_findings))
    return inserted


def _compute_fp(uf: UnifiedFinding) -> str:
    from app.workers.scanners.base import ScannerAdapter
    return ScannerAdapter.compute_fingerprint(
        uf.scanner, uf.scanner_rule_id or "", uf.location.target or "", uf.location.file_path or "",
        str(uf.location.line_start or ""),
    )


def _is_ignored(uf: UnifiedFinding, fp: str, rules: list[IgnoreRule]) -> bool:
    for r in rules:
        cond = r.rule or {}
        if cond.get("fingerprint") == fp:
            return True
        if cond.get("scanner") == uf.scanner and cond.get("rule_id") == uf.scanner_rule_id:
            return True
    return False


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_ORDER[a.value] >= _SEVERITY_ORDER[b.value] else b


def _upsert_group(db: Session, project_id: uuid.UUID, fp: str, title: str) -> None:
    grp = db.execute(
        select(FindingGroup).where(
            FindingGroup.project_id == project_id, FindingGroup.fingerprint == fp
        )
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if grp:
        grp.last_seen = now
        grp.occurrence_count += 1
    else:
        db.add(FindingGroup(
            project_id=project_id, fingerprint=fp, canonical_title=title[:512],
            first_seen=now, last_seen=now, occurrence_count=1,
        ))
