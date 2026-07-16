"""Trivy adapter — SCA + misconfig + secrets + SBOM."""
from __future__ import annotations

import json

from app.workers.scanners.base import ScannerAdapter
from app.schemas.finding import FindingLocation, UnifiedFinding


class TrivyAdapter(ScannerAdapter):
    name = "trivy"
    supports_kinds = ("repo", "image", "url")
    category = "sca"
    binary = "trivy"

    def build_command(self, raw_output_path: str) -> list[str]:
        target = self.ctx.target_value
        if self.ctx.target_kind == "repo":
            subcmd = "repo"
        elif self.ctx.target_kind == "image":
            subcmd = "image"
        else:
            subcmd = "fs"
        return [
            "trivy", subcmd, "--format", "json", "--output", raw_output_path,
            "--scanners", "vuln,secret,misconfig,license",
            "--quiet", "--skip-db-update", target,
        ]

    def parse(self, raw_output_path: str) -> list[UnifiedFinding]:
        with open(raw_output_path) as f:
            data = json.load(f)
        findings: list[UnifiedFinding] = []
        for result in data.get("Results", []):
            target = result.get("Target", self.ctx.target_value)
            cls = result.get("Class", "")
            # Vulnerabilities
            for v in result.get("Vulnerabilities", []) or []:
                sev = self.severity_from_string(v.get("Severity"))
                vid = v.get("VulnerabilityID", "")
                pkg = v.get("PkgName", "")
                fixed = v.get("FixedVersion")
                desc = v.get("Description", "")
                if fixed:
                    desc += f"\n\nFixed in: {fixed}"
                findings.append(UnifiedFinding(
                    scanner=self.name,
                    scanner_rule_id=vid,
                    category="sca",
                    severity=sev,
                    title=f"{vid}: {pkg} {v.get('InstalledVersion', '')}",
                    description=desc,
                    cvss=_extract_cvss(v),
                    cwe=_extract_cwe(v),
                    location=FindingLocation(type="file", target=target, file_path=target),
                    evidence=v,
                    fingerprint=self.compute_fingerprint(self.name, vid, pkg, target),
                ))
            # Secrets
            for s in result.get("Secrets", []) or []:
                sev = self.severity_from_string(s.get("Severity"))
                rid = s.get("RuleID", "")
                findings.append(UnifiedFinding(
                    scanner=self.name,
                    scanner_rule_id=rid,
                    category="secret",
                    severity=sev,
                    title=f"Secret exposed: {s.get('Title', rid)}",
                    description=s.get("Match", ""),
                    location=FindingLocation(
                        type="file", target=target, file_path=s.get("Filename", target),
                        line_start=s.get("StartLine"), line_end=s.get("EndLine"),
                        code_snippet=s.get("Match"),
                    ),
                    evidence=s,
                    fingerprint=self.compute_fingerprint(self.name, rid, s.get("Filename"), str(s.get("StartLine"))),
                ))
            # Misconfigurations
            for m in result.get("Misconfigurations", []) or []:
                sev = self.severity_from_string(m.get("Severity"))
                mid = m.get("AVDID") or m.get("ID", "")
                findings.append(UnifiedFinding(
                    scanner=self.name,
                    scanner_rule_id=mid,
                    category="misconfig",
                    severity=sev,
                    title=m.get("Title", mid),
                    description=m.get("Description"),
                    cwe=m.get("CWE"),
                    location=FindingLocation(type="file", target=target, file_path=target),
                    evidence=m,
                    fingerprint=self.compute_fingerprint(self.name, mid, target),
                ))
        return findings


def _extract_cvss(v: dict) -> float | None:
    cvss = v.get("CVSS")
    if isinstance(cvss, dict):
        for src in ("nvd", "redhat", "ghsa"):
            if src in cvss and isinstance(cvss[src], dict):
                v3 = cvss[src].get("V3Score") or cvss[src].get("V2Score")
                if v3:
                    return float(v3)
    return None


def _extract_cwe(v: dict) -> str | None:
    cwe = v.get("CweIDs") or v.get("CWE")
    if isinstance(cwe, list) and cwe:
        return str(cwe[0])
    if isinstance(cwe, str):
        return cwe
    return None
