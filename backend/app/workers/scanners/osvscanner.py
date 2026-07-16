"""OSV-Scanner adapter — open-source vulnerability scanning."""
from __future__ import annotations

import json

from app.workers.scanners.base import ScannerAdapter
from app.schemas.finding import FindingLocation, UnifiedFinding


class OSVScannerAdapter(ScannerAdapter):
    name = "osv-scanner"
    supports_kinds = ("repo", "image")
    category = "sca"
    binary = "osv-scanner"

    def build_command(self, raw_output_path: str) -> list[str]:
        cmd = ["osv-scanner", "--format", "json", "--output", raw_output_path]
        if self.ctx.target_kind == "repo":
            cmd += ["--recursive", self.ctx.target_value]
        else:
            cmd += [self.ctx.target_value]
        return cmd

    def parse(self, raw_output_path: str) -> list[UnifiedFinding]:
        with open(raw_output_path) as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return []
        findings: list[UnifiedFinding] = []
        for result in data.get("results", []):
            source = result.get("source", {})
            path = source.get("path", self.ctx.target_value)
            for pkg in result.get("packages", []):
                name = pkg.get("package", {}).get("name", "")
                for v in pkg.get("vulnerabilities", []):
                    vid = v.get("id", "")
                    sev = "high"
                    aliases = v.get("aliases", [])
                    findings.append(UnifiedFinding(
                        scanner=self.name,
                        scanner_rule_id=vid,
                        category="sca",
                        severity=sev,
                        title=f"{vid}: {name}",
                        description=v.get("summary", ""),
                        location=FindingLocation(type="file", target=path, file_path=path),
                        evidence={"id": vid, "aliases": aliases, "package": name, "summary": v.get("summary")},
                        fingerprint=self.compute_fingerprint(self.name, vid, name, path),
                    ))
        return findings
