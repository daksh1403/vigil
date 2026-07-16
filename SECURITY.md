# Security Policy

## Reporting a vulnerability

VIGIL is a security tool; we take vulnerabilities in VIGIL itself seriously.

- Email: security@vigil.local (replace with your address)
- Do NOT open a public issue for security vulnerabilities.
- Include reproduction steps and, if possible, a PoC.

We will acknowledge within 72 hours and aim for a fix within 30 days.

## Scope

Vulnerabilities in VIGIL's backend, worker, or frontend code. Out of scope:
findings produced BY VIGIL against third-party targets (that's the product working
as intended).

## Hardening notes for production

- Set a strong `SECRET_KEY` and `ENCRYPTION_KEY`.
- Run scanners in an isolated network with no egress to private ranges
  (`SCANNER_RESTRICT_LOCAL_NET=true`).
- Rotate the bootstrap superuser password immediately.
- Enable RBAC; grant `engineer`/`admin` only to trusted users.
- The LLM (Ollama) runs locally — no data leaves your machine.
