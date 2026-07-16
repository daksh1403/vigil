"""Bandit adapter — Python SAST."""
from __future__ import annotations

import json

from app.workers.scanners.base import ScannerAdapter
from app.schemas.finding import FindingLocation, UnifiedFinding

_BANDIT_SEV = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}


class BanditAdapter(ScannerAdapter):
    name = "bandit"
    supports_kinds = ("repo",)
    category = "vuln"
    binary = "bandit"

    def build_command(self, raw_output_path: str) -> list[str]:
        return [
            "bandit", "-r", self.ctx.target_value,
            "-f", "json", "-o", raw_output_path, "-q",
            "--ignore-nosec",
        ]

    def parse(self, raw_output_path: str) -> list[UnifiedFinding]:
        with open(raw_output_path) as f:
            data = json.load(f)
        findings: list[UnifiedFinding] = []
        for r in data.get("results", []):
            sev = _BANDIT_SEV.get(r.get("issue_severity", ""), "info")
            test_id = r.get("test_id", "")
            file = r.get("filename", "")
            line = r.get("line_number")
            cwe = r.get("issue_cwe", {}).get("id") if isinstance(r.get("issue_cwe"), dict) else None
            findings.append(UnifiedFinding(
                scanner=self.name,
                scanner_rule_id=test_id,
                scanner_confidence=0.7,
                category="vuln",
                severity=sev,
                title=r.get("issue_text", test_id),
                description=r.get("issue_text"),
                cwe=f"CWE-{cwe}" if cwe else None,
                location=FindingLocation(
                    type="file", target=self.ctx.target_value, file_path=file,
                    line_start=line, code_snippet=r.get("code"),
                ),
                evidence=r,
                fingerprint=self.compute_fingerprint(self.name, test_id, file, str(line)),
            ))
        return findings
