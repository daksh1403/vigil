"""AI Triage Pipeline — orchestrates the full enrichment of a finding.

Stages (each is independently valuable and logged):
  1. Embed finding (sentence-transformers) + semantic dedup (pgvector).
  2. FP classification (Isolation Forest / heuristic).
  3. LLM triage (Ollama) — explanation + ATT&CK/OWASP/CWE + fix (RAG-grounded).
  4. Unified risk scoring.

The LLM never decides if a finding is "real"; it enriches. A human confirms.
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.ai_triage import AITriage, FPLabel
from app.models.finding import Finding
from app.services.ai import dedup, embeddings, fp_classifier, llm_triage, risk_score

log = get_logger(__name__)


def triage_finding(db: Session, finding: Finding) -> AITriage:
    """Run the full AI triage pipeline on a single finding and persist results."""
    # 1) Embed + dedup
    emb = embeddings.embed_finding(
        finding.title, finding.description, finding.scanner, finding.cwe
    )
    dup_id = None
    if emb:
        dedup.store_embedding(db, finding.id, emb)
        dup_id = dedup.find_duplicates(db, finding, emb)

    # 2) FP classification
    fp = fp_classifier.classify(finding)

    # 3) LLM triage
    llm = llm_triage.triage_finding(finding)

    # 4) Risk score
    risk = risk_score.compute_risk(
        finding,
        fp_score=fp.fp_score,
        exploitability=risk_score.exploitability_heuristic(finding),
    )

    # Persist (upsert)
    triage = db.get(AITriage, finding.id)
    if triage is None:
        triage = AITriage(finding_id=finding.id)
        db.add(triage)

    triage.fp_score = fp.fp_score
    triage.fp_label = FPLabel(fp.label) if fp.label in ("likely_tp", "uncertain", "likely_fp") else None
    triage.risk_score = risk
    triage.mitre_tactics = llm.mitre_tactics
    triage.mitre_techniques = llm.mitre_techniques
    triage.owasp_id = llm.owasp_id
    triage.cwe_id = llm.cwe_id
    triage.explanation = llm.explanation
    triage.remediation = llm.remediation
    triage.llm_model = llm.model
    triage.prompt_version = llm_triage.PROMPT_VERSION if llm.method == "llm" else None
    triage.tokens_in = llm.tokens_in
    triage.tokens_out = llm.tokens_out
    triage.triage_method = llm.method

    db.flush()
    log.info(
        "ai.triage.done",
        finding_id=str(finding.id),
        fp=fp.fp_score,
        risk=risk,
        method=llm.method,
        dup=bool(dup_id),
    )
    return triage


def triage_scan_findings(db: Session, scan_id: uuid.UUID) -> int:
    """Run AI triage on all findings of a scan. Returns count triaged."""
    from app.models.finding import Finding
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    count = 0
    for f in findings:
        try:
            triage_finding(db, f)
            count += 1
            if count % 10 == 0:
                db.commit()
        except Exception as e:  # pragma: no cover — don't let one finding kill the batch
            log.error("ai.triage.failed", finding_id=str(f.id), error=str(e))
            db.rollback()
    db.commit()
    return count
