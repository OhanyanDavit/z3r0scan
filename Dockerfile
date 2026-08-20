# z3r0scan container.
#
# Bundles nmap for host scanning. The ProjectDiscovery tools (nuclei, httpx,
# subfinder, dnsx) are NOT installed here — the orchestrator falls back to its
# pure-Python implementations when they are absent, and modules that truly need
# an external tool (nuclei) skip cleanly. To build an image that includes those
# tools, add a pinned, checksum-verified install stage (tracked as a follow-up).
#
# Build: docker build -t z3r0scan .
# Run:   docker run --rm -v "$PWD/reports:/reports" z3r0scan example.com -y --html report.html
FROM python:3.12-slim

# nmap for host scanning; ca-certificates for HTTPS enrichment calls.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# Install with the web dashboard + AI analysis extras so the container is
# full-featured out of the box (bring your own API key at runtime).
RUN pip install --no-cache-dir ".[all]"

# Drop root; scanning does not need it for connect scans. Give the non-root user
# a writable output directory so `--html /reports/out.html` works out of the box.
RUN useradd --create-home scanner \
    && mkdir -p /reports \
    && chown scanner:scanner /reports
USER scanner
WORKDIR /reports

ENTRYPOINT ["z3r0scan"]
CMD ["--help"]
