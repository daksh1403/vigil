# VIGIL — Open-Source AI-Powered AppSec & Code Security Platform

[![CI](https://github.com/daksh/vigil/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**VIGIL** is a local-first, fully open-source security platform that orchestrates the best
open-source scanners (Nuclei, OWASP ZAP, Semgrep, Trivy, Gitleaks, OSV-Scanner, Bandit and more)
behind a single API and UI, then applies an **AI triage engine** to deduplicate, prioritize,
explain, and map findings to MITRE ATT&CK / OWASP / CWE — for free, on a laptop.

> **Why VIGIL?** Modern scanners are excellent but flood you with duplicated, false-positive-laden
> raw output. VIGIL's value-add is *post-scan intelligence*: one normalized schema, cross-scanner
> dedup, classical-ML false-positive reduction, and local-LLM explanations + fixes. That is exactly
> what Semgrep Assistant and GitHub Copilot Autofix do commercially — but free and private.

## Highlights

- **Orchestration-first** — never rebuilds scanners; wraps Nuclei / ZAP / Semgrep / Trivy / Gitleaks
  / OSV-Scanner / Bandit / Syft / pip-audit behind a common `ScannerAdapter` interface.
- **Unified Finding Schema (UFS)** — every scanner's output normalizes to one schema, enabling
  cross-tool dedup and a uniform UI.
- **AI Triage Engine (justified, not marketing)**
  - Embedding-based dedup (`pgvector`) — groups the same vuln reported by Nuclei + ZAP + Semgrep.
  - Classical-ML false-positive reduction (Isolation Forest / LOF) — interpretable, no GPU.
  - Local-LLM (Ollama: Llama 3 / Qwen / Mistral / Phi) explanation + fix + ATT&CK/OWASP/CWE mapping
    via a free RAG knowledge base (NVD / OWASP / ATT&CK).
  - Unified risk score (CVSS × EPSS × exploitability × asset criticality × FP-confidence).
- **Production-grade architecture** — FastAPI + Celery + Redis + PostgreSQL(+pgvector) + Next.js,
  JWT/RBAC auth, rate limiting, structured logging, Prometheus/Grafana/Loki observability.
- **100% free** — no paid APIs, no paid datasets, no cloud GPUs. Runs on an Apple Silicon MacBook.
- **Docker-native** — `make up` brings the whole stack online.

## Quick start

```bash
git clone https://github.com/daksh/vigil.git && cd vigil
cp .env.example .env
make up            # postgres, redis, backend, worker, frontend, ollama, prometheus, grafana
make migrate       # apply DB migrations + pgvector
make seed-demo     # demo project + sample findings
open http://localhost:3000   # frontend
open http://localhost:8000/docs # API
```

Default credentials: `admin@vigil.dev` / `vigiladmin` (change in production).

## Scanners bundled

| Domain | Tools |
|---|---|
| DAST / web | Nuclei, OWASP ZAP, Katana (crawl), httpx |
| SAST | Semgrep, Bandit |
| SCA / SBOM | Trivy, OSV-Scanner, Syft, Grype, pip-audit |
| Secrets | Gitleaks |

## AI — what we use, and what we deliberately *don't*

| Sub-problem | Method | Why |
|---|---|---|
| Scanning | Off-the-shelf tools | Solved problem |
| Dedup | Embeddings + cosine (pgvector) | Semantic match beats exact |
| False-positive reduction | Isolation Forest / LOF | Interpretable, no GPU, no labels needed |
| Explanation / fix / mapping | Local LLM (Ollama) + RAG | The commercial value prop, free |
| Risk scoring | Rules + light ML | Transparent & auditable |

**Deliberately NOT used:** LogBERT / DeepLog / LSTM / Transformer for finding triage — they target
*log-line* anomaly detection (SIEM domain), require labelled breach data and GPUs, and add opacity.
The app-finding domain is better served by classical ML + LLM reasoning.

## Project layout

See [ARCHITECTURE.md](ARCHITECTURE.md). Key areas:

```
backend/   FastAPI + Celery + SQLAlchemy + AI triage services
frontend/  Next.js 15 (React 19) + Tailwind + shadcn/ui
scanner-bin/  fat image bundling all scanner CLIs
rag-kb/    NVD/OWASP/ATT&CK ingestion into the vector KB
deploy/    docker, k8s, helm, grafana, prometheus
```

## Development

```bash
make dev          # compose with hot reload
make lint         # ruff + mypy + eslint
make test         # pytest + vitest
make shell        # shell into backend container
make logs         # tail all services
```

## License

MIT. See [LICENSE](LICENSE).
