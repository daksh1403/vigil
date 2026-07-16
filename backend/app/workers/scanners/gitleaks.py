"""Gitleaks adapter — secret detection in git repos."""
from __future__ import annotations

import json

from app.workers.scanners.base import ScannerAdapter
from app.schemas.finding import FindingLocation, UnifiedFinding


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    supports_kinds = ("repo",)
    category = "secret"
    binary = "gitleaks"

    def build_command(self, raw_output_path: str) -> list[str]:
        return [
            "gitleaks", "git",
            "--source", self.ctx.target_value,
            "--report-format", "json",
            "--report-path", raw_output_path,
            "--no-banner",
            "--redact",  # don't log full secrets
            "--exit-code", "0",  # don't fail the scan on findings
        ]

    def parse(self, raw_output_path: str) -> list[UnifiedFinding]:
        with open(raw_output_path) as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
        findings: list[UnifiedFinding] = []
        for leak in data:
            rid = leak.get("RuleID", "")
            file = leak.get("File", "")
            line = leak.get("StartLine")
            sev = "high" if any(k in rid.lower() for k in ("key", "token", "password", "secret", "credential")) else "medium"
            findings.append(UnifiedFinding(
                scanner=self.name,
                scanner_rule_id=rid,
                category="secret",
                severity=sev,
                title=f"Hardcoded secret: {rid}",
                description=f"Potential {rid} detected in {file} (commit {leak.get('Commit', '')[:8]}).",
                location=FindingLocation(
                    type="file", target=self.ctx.target_value, file_path=file,
                    line_start=line, line_end=leak.get("EndLine"),
                    code_snippet=leak.get("Secret", "[redacted]"),
                ),
                evidence={k: v for k, v in leak.items() if k != "Secret"},
                fingerprint=leak.get("Fingerprint") or self.compute_fingerprint(self.name, rid, file, str(line)),
            ))
        return findings
