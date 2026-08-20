# z3r0scan — ships with the real recon tools so the orchestrator runs at full
# power out of the box (nmap; nuclei is pulled in via the projectdiscovery image
# layer or can be added). Build: docker build -t z3r0scan .
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

# Drop root; scanning does not need it for connect scans.
RUN useradd --create-home scanner
USER scanner

ENTRYPOINT ["z3r0scan"]
CMD ["--help"]
