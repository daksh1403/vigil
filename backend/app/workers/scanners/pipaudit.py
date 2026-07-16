"""pip-audit adapter — Python dependency vulnerability scanning."""
from __future__ import annotations

import json

from app.workers.scanners.base import ScannerAdapter
from app.schemas.finding import FindingLocation, UnifiedFinding


class PipAuditAdapter(ScannerAdapter):
    name = "pip-audit"
    supports_kinds = ("repo",)
    category = "sca"
    binary = "pip-audit"

    def build_command(self, raw_output_path: str) -> list[str]:
        return [
            "pip-audit",
            "--requirement", self._find_requirements(),
            "--format", "json",
            "--output", raw_output_path,
            "--no-deps",
        ]

    def _find_requirements(self) -> str:
        import os
        for name in ("requirements.txt", "requirements.in"):
            p = os.path.join(self.ctx.target_value, name)
            if os.path.exists(p):
                return p
        # Fallback: create empty so pip-audit reports nothing rather than crash
        return self._write_input([], "requirements.txt")

    def parse(self, raw_output_path: str) -> list[UnifiedFinding]:
        with open(raw_output_path) as f:
            data = json.load(f)
        findings: list[UnifiedFinding] = []
        for dep in data.get("dependencies", []):
            name = dep.get("name", "")
            version = dep.get("version", "")
            for v in dep.get("vulns", []):
                vid = v.get("id", "")
                sev = "high" if v.get("fix_versions") else "medium"
                findings.append(UnifiedFinding(
                    scanner=self.name,
                    scanner_rule_id=vid,
                    category="sca",
                    severity=sev,
                    title=f"{vid}: {name}=={version}",
                    description=v.get("description", "")[:500],
                    location=FindingLocation(type="file", target=self.ctx.target_value, file_path="requirements.txt"),
                    evidence={"id": vid, "package": name, "version": version, "fix_versions": v.get("fix_versions")},
                    fingerprint=self.compute_fingerprint(self.name, vid, name, version),
                ))
        return findings
