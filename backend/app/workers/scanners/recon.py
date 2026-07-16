"""Katana + httpx adapters — crawling and host probing (recon feeders)."""
from __future__ import annotations

import json

from app.workers.scanners.base import ScannerAdapter
from app.schemas.finding import FindingLocation, UnifiedFinding


class KatanaAdapter(ScannerAdapter):
    """Crawls a web app and emits discovered URLs as info findings + a URL list
    that downstream DAST scanners (Nuclei) can consume."""

    name = "katana"
    supports_kinds = ("url",)
    category = "info"
    binary = "katana"

    def build_command(self, raw_output_path: str) -> list[str]:
        return [
            "katana", "-u", self.ctx.target_value,
            "-jc", "-d", "2",
            "-o", raw_output_path,
            "-silent",
        ]

    def parse(self, raw_output_path: str) -> list[UnifiedFinding]:
        findings: list[UnifiedFinding] = []
        urls: list[str] = []
        with open(raw_output_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("{"):
                    try:
                        d = json.loads(line)
                        url = d.get("request", {}).get("endpoint", "")
                    except json.JSONDecodeError:
                        continue
                else:
                    url = line
                if url:
                    urls.append(url)
        # Emit one info finding summarizing crawl surface
        if urls:
            findings.append(UnifiedFinding(
                scanner=self.name,
                scanner_rule_id="crawl-surface",
                category="info",
                severity="info",
                title=f"Crawled {len(urls)} endpoints from {self.ctx.target_value}",
                description="Discovered endpoints available for DAST scanning.",
                location=FindingLocation(type="url", target=self.ctx.target_value),
                evidence={"endpoints": urls[:500]},
                fingerprint=self.compute_fingerprint(self.name, "crawl-surface", self.ctx.target_value),
            ))
        return findings


class HttpxAdapter(ScannerAdapter):
    """Probes hosts for liveness + tech fingerprint."""

    name = "httpx"
    supports_kinds = ("url",)
    category = "info"
    binary = "httpx"

    def build_command(self, raw_output_path: str) -> list[str]:
        return [
            "httpx", "-u", self.ctx.target_value,
            "-json", "-silent",
            "-o", raw_output_path,
            "-tech-detect", "-status-code", "-title", "-web-server",
        ]

    def parse(self, raw_output_path: str) -> list[UnifiedFinding]:
        findings: list[UnifiedFinding] = []
        with open(raw_output_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                tech = d.get("tech", [])
                findings.append(UnifiedFinding(
                    scanner=self.name,
                    scanner_rule_id="tech-detect",
                    category="info",
                    severity="info",
                    title=f"Tech fingerprint: {', '.join(tech) if tech else d.get('title', 'unknown')}",
                    description=f"HTTP {d.get('status_code')} — server: {d.get('webserver', '?')}",
                    location=FindingLocation(type="url", target=d.get("url", self.ctx.target_value)),
                    evidence=d,
                    fingerprint=self.compute_fingerprint(self.name, "tech-detect", d.get("url", "")),
                ))
        return findings
