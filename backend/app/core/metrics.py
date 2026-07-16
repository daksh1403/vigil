"""Custom Prometheus metrics for VIGIL."""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

findings_total = Counter("vigil_findings_total", "Total findings ingested", ["scanner", "severity"])
scans_running = Gauge("vigil_scans_running", "Currently running scans")
scans_total = Counter("vigil_scans_total", "Total scans started", ["status"])
fp_rate = Gauge("vigil_fp_rate", "False-positive rate (0..1)")
triage_latency = Histogram("vigil_triage_latency_seconds", "AI triage latency", ["method"])
llm_tokens = Counter("vigil_llm_tokens_total", "LLM tokens used", ["direction"])
