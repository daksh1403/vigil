# Contributing to VIGIL

Thanks for your interest! VIGIL is orchestration-first — the easiest ways to contribute:

## Add a scanner

1. Subclass `ScannerAdapter` in `backend/app/workers/scanners/`.
2. Implement `build_command()` (CLI argv) and `parse()` (native output → `UnifiedFinding` list).
3. Register it in `backend/app/workers/scanners/registry.py`.
4. Add a test with a sample of the tool's native output in `backend/tests/`.

The orchestrator and UI pick up new scanners automatically.

## Improve the AI triage

- Add to the RAG KB (`rag-kb/scripts/build_kb.py`).
- Improve the FP classifier features (`backend/app/services/ai/fp_classifier.py`).
- Refine prompts (`llm/prompts/`).

## Dev setup

```bash
cp .env.example .env
make dev
make migrate
make seed-demo
make test
make lint
```

## Conventions

- Python: ruff + mypy. No new dependencies without justification.
- Commits: conventional (`feat:`, `fix:`, `docs:`).
- Keep scanners as black-box subprocesses — do not couple them to the DB layer.
