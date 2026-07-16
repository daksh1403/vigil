"""Nuclei adapter — template-based DAST scanner."""
from __future__ import annotations

import json

from app.workers.scanners.base import ScannerAdapter, ScanContext
from app.schemas.finding import FindingLocation, UnifiedFinding


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    supports_kinds = ("url",)
    category = "vuln"
    binary = "nuclei"

    def build_command(self, raw_output_path: str) -> list[str]:
        rate = str(settings.scanner_rate_limit) if (settings := __import__("app.core.config", fromlist=["settings"]).settings) else "150"
        cmd = [
            "nuclei",
            "-u", self.ctx.target_value,
            "-jsonl",
            "-o", raw_output_path,
            "-rate-limit", rate,
            "-silent",
            "-no-color",
        ]
        if settings.scanner_restrict_local_net:
            cmd.append("-lna")  # restrict local network access
        return cmd

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
                sev = self.severity_from_string(d.get("info", {}).get("severity"))
                template_id = d.get("template-id") or d.get("templateID", "")
                matched = d.get("matched-at") or d.get("matched", "")
                title = d.get("info", {}).get("name", template_id or "Nuclei finding")
                desc = d.get("info", {}).get("description")
                tags = d.get("info", {}).get("tags", {})
                cwe = None
                if isinstance(tags, dict) and tags.get("cwe"):
                    cwes = tags["cwe"]
                    if isinstance(cwes, list) and cwes:
                        cwe = str(cwes[0]).split("-")[-1] if "-" in str(cwes[0]) else str(cwes[0])
                        cwe = "CWE-" + cwe.replace("CWE-", "")
                cvss = d.get("info", {}).get("classification", {}).get("cvss-score")
                findings.append(UnifiedFinding(
                    scanner=self.name,
                    scanner_rule_id=template_id,
                    category="vuln",
                    severity=sev,
                    title=title,
                    description=desc,
                    cvss=float(cvss) if cvss else None,
                    cwe=cwe,
                    location=FindingLocation(type="url", target=matched or self.ctx.target_value),
                    evidence=d,
                    fingerprint=self.compute_fingerprint(self.name, template_id, matched),
                ))
        return findings
