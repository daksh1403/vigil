# VIGIL Architecture

## Design principles

1. **Orchestration-first.** Scanners are black-box subprocesses. VIGIL owns normalization,
   correlation, triage, and presentation — never the scanning itself.
2. **AI as a stage, not a crutch.** AI earns its place per sub-problem (see README). Classical ML
   handles FP reduction; LLMs handle explanation/mapping/fix. The LLM never decides if a finding
   is "real" (hallucination risk) — it enriches, a human confirms.
3. **Graceful degradation.** If Ollama is absent, the platform falls back to deterministic triage.
4. **Local-first, deployable later.** Everything runs on a laptop via Docker Compose; the same
   images deploy to Kubernetes.

## System diagram

```
Frontend (Next.js) ──REST/WS──▶ FastAPI Gateway (auth, RBAC, rate-limit)
                                    │
            ┌───────────────────────┼──────────────────────┐
            ▼ enqueue               ▼ read/write            ▼ /metrics
        Redis (broker)          PostgreSQL(+pgvector)    Prometheus/Grafana/Loki
            │ tasks
            ▼
   Celery Worker Pool
   ┌────────┬────────┬────────┬────────┬────────┐
   │ DAST   │ SAST   │ SCA    │Secrets │ SBOM   │   (ScannerAdapter subclasses)
   │Nuclei  │Semgrep │Trivy   │Gitleaks│Syft    │
   │ZAP     │Bandit  │OSV-Sc  │        │        │
   └───┬────┴───┬────┴───┬────┴───┬────┴───┬────┘
       └────────┴────────┴────────┴────────┘
                       │ raw JSONL/SARIF
                       ▼
            Normalizer → Unified Finding Schema (UFS)
                       │
                       ▼
            AI Triage Pipeline
            1) Embedding dedup (pgvector)
            2) FP classifier (Isolation Forest)
            3) LLM (Ollama) explanation + ATT&CK/OWASP/CWE + fix (RAG)
            4) Risk scoring
                       │
                       ▼
            PostgreSQL (findings + ai_triage)
```

## Request lifecycle (one scan)

1. `POST /api/v1/scans` → validate, RBAC, persist `scans` row (`pending`), enqueue Celery task.
2. Orchestrator fans out one `ScannerAdapter.run()` per selected scanner (subprocess/CLI).
3. Each adapter parses tool output → list of **UFS** dicts.
4. Normalizer persists findings; computes stable `fingerprint`.
5. AI triage: embed → dedup vs history → FP score → LLM enrich → risk score.
6. WebSocket streams progress; findings appear live in the UI.
7. `scans.status = completed`; report generator (SARIF/HTML/PDF) available.

## Unified Finding Schema (UFS)

The single normalized contract every adapter emits. See `backend/app/schemas/finding.py`. Enables
cross-scanner dedup and a uniform UI/API regardless of which tool produced a finding.

## Data model

See `backend/app/models/` and `ARCHITECTURE.md#schema` (mirrors the design doc). Key tables:
`users`, `projects`, `targets`, `scans`, `scan_tasks`, `findings`, `ai_triage`,
`finding_groups`, `ignore_rules`, `scan_diffs`, `audit_log`, `webhooks`, `reports`.

## AI triage internals

- **Embeddings:** `sentence-transformers/all-MiniLM-L6-v2` (384-dim) stored in `findings.embedding`
  via `pgvector`. Dedup = cosine similarity > threshold within a project.
- **FP classifier:** `sklearn` Isolation Forest trained on tabular features
  (CVSS, EPSS, scanner confidence, context flags, historical analyst verdicts). Output: `fp_score`
  in [0,1]; `fp_label ∈ {likely_tp, uncertain, likely_fp}`. Model artifact in `ml/registry/`.
- **LLM triage:** Ollama (`llama3.1:8b` default). Prompt versioned in `llm/prompts/`. RAG retrieval
  over NVD/OWASP/ATT&CK embeddings in `pgvector`. Output: explanation, remediation, mapped IDs.
- **Risk score:** `risk = clip01( cvss/10 * epss * exploitability * asset_criticality * (1-fp_score) ) * 10`.

## Security model

- JWT access (15m) + refresh (7d), bcrypt password hashing.
- RBAC roles: `viewer`, `analyst`, `engineer`, `admin` — enforced per route via dependency.
- Per-user rate limiting (slowapi). Structured JSON logs with request IDs.
- Scanners run sandboxed: repo scans have no network egress by default; DAST scans run in an
  isolated Docker network. Secrets in `auth_profiles` encrypted at rest (Fernet).
- The platform never exfiltrates scanned code or secrets — all processing is local.

## Observability

- Prometheus scrapes `/metrics` (backend + worker). Grafana dashboards for scan throughput, finding
  rates, FP rate, LLM latency/tokens. Loki aggregates structured logs.

## Extending

Add a scanner: subclass `ScannerAdapter` (`backend/app/workers/scanners/base.py`), implement
`run()` + `parse()`, register in the registry. The orchestrator and UI pick it up automatically.
