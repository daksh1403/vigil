"""LLM triage via Ollama (local, free).

The LLM is confined to *enrichment* — explanation, MITRE ATT&CK / OWASP / CWE
mapping, and fix suggestions — never to deciding whether a finding is "real"
(hallucination risk). A human reviews. If Ollama is unavailable, the platform
degrades gracefully to deterministic triage (llm_fallback=true).
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import httpx
from app.core.config import settings
from app.core.logging import get_logger
from app.models.finding import Finding

log = get_logger(__name__)

PROMPT_VERSION = "v1"


@dataclass
class LLMResult:
    explanation: str
    remediation: str
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    owasp_id: str | None
    cwe_id: str | None
    model: str
    tokens_in: int
    tokens_out: int
    method: str  # llm | fallback


_SYSTEM = (
    "You are VIGIL, a senior application security engineer. Analyze the security finding "
    "and respond with a JSON object containing these exact keys:\n"
    '{"explanation": "plain-English summary of the vulnerability and its impact",\n'
    ' "remediation": "concrete steps to fix it",\n'
    ' "mitre_tactics": ["TacticID"],\n'
    ' "owasp_id": "A01",\n'
    ' "cwe_id": "CWE-XXX"}\n'
    "Do NOT echo the input. Generate new analysis text only."
)


def _build_prompt(finding: Finding) -> str:
    sev = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
    loc = finding.file_path or finding.target_ref or "n/a"
    return json.dumps({
        "scanner": finding.scanner,
        "rule_id": finding.scanner_rule_id,
        "title": finding.title,
        "description": (finding.description or "")[:800],
        "severity": sev,
        "cvss": finding.cvss,
        "cwe": finding.cwe,
        "owasp": finding.owasp_category,
        "location": loc,
        "code_snippet": (finding.code_snippet or "")[:500],
    }, indent=2)


def triage_finding(finding: Finding) -> LLMResult:
    if not settings.llm_enabled:
        return _fallback(finding)

    prompt = _build_prompt(finding)
    try:
        with httpx.Client(timeout=settings.llm_timeout) as client:
            resp = client.post(
                f"{settings.ollama_base_url}/api/generate",
                json={
                    "model": settings.ollama_model,
                    "prompt": prompt,
                    "system": _SYSTEM,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.2, "num_predict": 512},
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        log.warning("llm.unavailable_fallback", error=str(e), finding_id=str(finding.id))
        if settings.llm_fallback:
            return _fallback(finding)
        raise

    raw = data.get("response", "{}")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"explanation": raw[:1000], "remediation": ""}

    explanation = parsed.get("explanation", "") or ""
    if not explanation:
        explanation = (
            parsed.get("description", "")
            or parsed.get("summary", "")
            or parsed.get("analysis", "")
            or raw[:1000]
        )

    remediation = parsed.get("remediation", "") or ""
    if not remediation:
        remediation = parsed.get("fix", "") or parsed.get("recommendation", "") or ""

    return LLMResult(
        explanation=explanation[:4000],
        remediation=remediation[:4000],
        mitre_tactics=_as_list(parsed.get("mitre_tactics")),
        mitre_techniques=_as_list(parsed.get("mitre_techniques")),
        owasp_id=parsed.get("owasp_id"),
        cwe_id=parsed.get("cwe_id") or finding.cwe,
        model=settings.ollama_model,
        tokens_in=data.get("prompt_eval_count", 0) or 0,
        tokens_out=data.get("eval_count", 0) or 0,
        method="llm",
    )


def _fallback(finding: Finding) -> LLMResult:
    """Deterministic triage when no LLM is available."""
    sev = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
    explanation = (
        f"{finding.scanner} reported a {sev} severity finding: {finding.title}. "
        f"{'CWE: ' + finding.cwe + '. ' if finding.cwe else ''}"
        f"Located at {finding.file_path or finding.target_ref or 'the target'}."
    )
    remediation = "Review the finding and apply the relevant secure-coding fix. See CWE/OWASP references."
    return LLMResult(
        explanation=explanation,
        remediation=remediation,
        mitre_tactics=[],
        mitre_techniques=[],
        owasp_id=finding.owasp_category,
        cwe_id=finding.cwe,
        model="none",
        tokens_in=0,
        tokens_out=0,
        method="fallback",
    )


def _as_list(v) -> list[str]:
    if not v:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]
