"""Build the RAG knowledge base from free public sources.

Ingests:
  - MITRE ATT&CK (STIX/JSON, https://github.com/mitre/cti)
  - OWASP Top 10 (bundled)
  - CWE subset (bundled; full list from https://cwe.mitre.org)

Embeds each entry with sentence-transformers and writes to the pgvector
knowledge_base table, so the LLM triage can ground explanations in
authoritative references. All sources are free and open.

Usage: python -m rag-kb.scripts.build_kb
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))

KB_ENTRIES = [
    {"id": "TA0001", "type": "mitre_tactic", "name": "Initial Access", "text": "The adversary is trying to get into your network."},
    {"id": "TA0002", "type": "mitre_tactic", "name": "Execution", "text": "The adversary is trying to run malicious code."},
    {"id": "TA0006", "type": "mitre_tactic", "name": "Credential Access", "text": "The adversary is trying to steal account names and passwords."},
    {"id": "TA0007", "type": "mitre_tactic", "name": "Discovery", "text": "The adversary is trying to figure out your environment."},
    {"id": "T1190", "type": "mitre_technique", "name": "Exploit Public-Facing Application", "text": "Adversaries attempt to exploit a weakness in an internet-facing system."},
    {"id": "T1059", "type": "mitre_technique", "name": "Command and Scripting Interpreter", "text": "Abuse command/scripting interpreters to execute commands."},
    {"id": "T1552", "type": "mitre_technique", "name": "Unsecured Credentials", "text": "Search for credentials in files, repos, or memory."},
    {"id": "T1083", "type": "mitre_technique", "name": "File and Directory Discovery", "text": "Enumerate files and directories to find valuable data."},
    {"id": "A01", "type": "owasp", "name": "Broken Access Control", "text": "Restrictions on what authenticated users can do are not properly enforced."},
    {"id": "A02", "type": "owasp", "name": "Cryptographic Failures", "text": "Failures related to cryptography leading to exposure of sensitive data."},
    {"id": "A03", "type": "owasp", "name": "Injection", "text": "Untrusted data sent as part of a command or query (SQLi, XSS, etc.)."},
    {"id": "A05", "type": "owasp", "name": "Security Misconfiguration", "text": "Missing hardening, default accounts, verbose errors, open cloud storage."},
    {"id": "A06", "type": "owasp", "name": "Vulnerable and Outdated Components", "text": "Using components with known vulnerabilities (CVEs)."},
    {"id": "CWE-79", "type": "cwe", "name": "XSS", "text": "Improper neutralization of input during web page generation."},
    {"id": "CWE-89", "type": "cwe", "name": "SQL Injection", "text": "Improper neutralization of special elements in SQL query."},
    {"id": "CWE-502", "type": "cwe", "name": "Deserialization", "text": "Deserialization of untrusted data can lead to RCE."},
    {"id": "CWE-798", "type": "cwe", "name": "Hardcoded Credentials", "text": "Use of hard-coded credentials in source/config."},
    {"id": "CWE-200", "type": "cwe", "name": "Information Exposure", "text": "Sensitive information exposed to an actor not explicitly authorized."},
    {"id": "CWE-22", "type": "cwe", "name": "Path Traversal", "text": "Improper limitation of a pathname to a restricted directory."},
    {"id": "CWE-918", "type": "cwe", "name": "SSRF", "text": "Server-Side Request Forgery."},
]


def build() -> None:
    from app.core.db import SessionLocal
    from app.core.logging import configure_logging, get_logger
    from app.services.ai.embeddings import embed_text
    from sqlalchemy import text

    configure_logging()
    log = get_logger(__name__)

    with SessionLocal() as db:
        db.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        db.execute(text("""
            CREATE TABLE IF NOT EXISTS knowledge_base (
                id TEXT PRIMARY KEY,
                type TEXT, name TEXT, text TEXT,
                embedding vector(384)
            )
        """))
        count = 0
        for entry in KB_ENTRIES:
            emb = embed_text(f"{entry['id']} {entry['name']}. {entry['text']}") or []
            db.execute(text("DELETE FROM knowledge_base WHERE id = :id"), {"id": entry["id"]})
            db.execute(text(
                "INSERT INTO knowledge_base (id, type, name, text, embedding) "
                "VALUES (:id, :type, :name, :text, CAST(:emb AS vector))"
            ), {**entry, "emb": str(emb)})
            count += 1
        db.commit()
        log.info("rag_kb.built", entries=count)


if __name__ == "__main__":
    build()
