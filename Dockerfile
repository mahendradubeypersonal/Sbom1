# sbom-fixer image (ADR-08): Python, the tool and a pinned sbomqs, so Jenkins agents need nothing else.
# Build: docker build -t sbom-fixer:1.0.0 .
# Run:   docker run --rm -v "$PWD:/work" -w /work sbom-fixer:1.0.0 fix build/sbom.json --out build/sbom-fixed
FROM python:3.12-slim

ARG SBOMQS_VERSION=1.0.0
# Confirm the release asset name for the pinned version at https://github.com/interlynk-io/sbomqs/releases
ARG SBOMQS_URL=https://github.com/interlynk-io/sbomqs/releases/download/v${SBOMQS_VERSION}/sbomqs-linux-amd64

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL "${SBOMQS_URL}" -o /usr/local/bin/sbomqs \
 && chmod +x /usr/local/bin/sbomqs \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sbom-fixer
COPY pyproject.toml README.md ./
COPY sbom_fixer ./sbom_fixer
RUN pip install --no-cache-dir . && useradd --create-home fixer

USER fixer
ENTRYPOINT ["sbom-fixer"]
CMD ["--help"]
