"""Semgrep adapter — multi-language SAST."""
from __future__ import annotations

import json

from app.workers.scanners.base import ScannerAdapter
from app.schemas.finding import FindingLocation, UnifiedFinding


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    supports_kinds = ("repo",)
    category = "vuln"
    binary = "semgrep"

    def build_command(self, raw_output_path: str) -> list[str]:
        return [
            "semgrep", "scan",
            "--config", "auto",
            "--json",
            "--output", raw_output_path,
            "--quiet",
            "--metrics=off",
            "--no-git-ignore",
            self.ctx.target_value,
        ]

    def parse(self, raw_output_path: str) -> list[UnifiedFinding]:
        with open(raw_output_path) as f:
            data = json.load(f)
        findings: list[UnifiedFinding] = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            sev = self.severity_from_string(extra.get("severity"))
            rule_id = r.get("check_id", "")
            path = r.get("path", "")
            start = r.get("start", {})
            line = start.get("line")
            snippet = extra.get("lines")
            cwe = None
            metadata = extra.get("metadata", {})
            if isinstance(metadata.get("cwe"), list) and metadata["cwe"]:
                cwe = str(metadata["cwe"][0]).split(":")[0]
            elif isinstance(metadata.get("cwe"), str):
                cwe = metadata["cwe"].split(":")[0]
            owasp = metadata.get("owasp")
            if isinstance(owasp, list) and owasp:
                owasp = owasp[0]
            findings.append(UnifiedFinding(
                scanner=self.name,
                scanner_rule_id=rule_id,
                scanner_confidence=0.8,
                category="vuln",
                severity=sev,
                title=extra.get("message", rule_id),
                description=extra.get("message"),
                cwe=cwe,
                owasp_category=str(owasp) if owasp else None,
                location=FindingLocation(
                    type="file", target=self.ctx.target_value, file_path=path,
                    line_start=line, line_end=r.get("end", {}).get("line"), code_snippet=snippet,
                ),
                evidence=r,
                fingerprint=self.compute_fingerprint(self.name, rule_id, path, str(line)),
            ))
        return findings
