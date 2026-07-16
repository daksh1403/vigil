# Fat image bundling all open-source scanner CLIs.
# Used by the Celery worker to run scanners as subprocesses.
# All scanners are built/installed from source or official installers for portability.

FROM golang:1.25-bookworm AS go-builder
ENV CGO_ENABLED=0 GOTOOLCHAIN=auto
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/zricethezav/gitleaks/v8@latest
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@latest

FROM python:3.12-slim
LABEL org.opencontainers.image.title="vigil-scanner-bin"
LABEL org.opencontainers.image.description="Bundled open-source security scanners for VIGIL"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl jq ca-certificates nmap wget bash && \
    rm -rf /var/lib/apt/lists/*

# Go-built scanner binaries
COPY --from=go-builder /go/bin /usr/local/bin

# Python scanners (bandit, pip-audit, semgrep)
RUN pip install --no-cache-dir bandit pip-audit semgrep

# Trivy via official install script
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Pre-download nuclei templates
RUN mkdir -p /data/nuclei-templates && nuclei -update-templates -silent || true

# Smoke check: list installed scanners
RUN for b in nuclei katana httpx subfinder gitleaks osv-scanner bandit pip-audit semgrep trivy nmap; do \
      command -v $b >/dev/null && echo "OK: $b -> $(command -v $b)" || echo "MISSING: $b"; \
    done

VOLUME ["/data"]
ENTRYPOINT ["sleep", "infinity"]
