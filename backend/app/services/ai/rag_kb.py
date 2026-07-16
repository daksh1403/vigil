"""RAG knowledge base for vulnerability context retrieval.

Ingests public CVE (NVD), OWASP Top 10, and MITRE ATT&CK data into the pgvector
store so the LLM triage can ground explanations in authoritative references.
All sources are free and open. The build script lives in rag-kb/scripts/.
"""
from __future__ import annotations

from app.core.logging import get_logger

log = get_logger(__name__)


def retrieve_context(cwe: str | None, owasp: str | None, title: str) -> list[str]:
    """Retrieve relevant KB snippets for a finding.

    Returns a list of context strings to inject into the LLM prompt. Currently
    a lightweight keyword match over a small bundled KB; designed to be backed
    by pgvector similarity search once the KB is built.
    """
    snippets: list[str] = []
    if cwe and cwe in _CWE_KB:
        snippets.append(f"{cwe}: {_CWE_KB[cwe]}")
    if owasp and owasp.upper() in _OWASP_KB:
        snippets.append(f"{owasp.upper()}: {_OWASP_KB[owasp.upper()]}")
    return snippets


# Minimal bundled KB (extended by rag-kb/scripts/build_kb.py from NVD/OWASP/ATT&CK).
_CWE_KB = {
    "CWE-79": "Cross-site Scripting (XSS): unsanitized input rendered in the browser.",
    "CWE-89": "SQL Injection: untrusted input concatenated into SQL queries.",
    "CWE-502": "Deserialization of Untrusted Data: can lead to RCE (e.g. Log4Shell).",
    "CWE-22": "Path Traversal: file access outside intended directory.",
    "CWE-352": "CSRF: state-changing request forged from another origin.",
    "CWE-798": "Hard-coded Credentials: secrets committed to source.",
    "CWE-200": "Information Exposure: sensitive data disclosed to unauthorized actors.",
    "CWE-287": "Improper Authentication.",
    "CWE-918": "SSRF: server-side request forgery.",
}

_OWASP_KB = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection (XSS, SQLi, etc.)",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}
