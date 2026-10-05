# sbom-fixer image (ADR-08): Python, the tool and a pinned sbomqs, so Jenkins agents need nothing else.
# Build: docker build -t sbom-fixer:1.0.0 .
# Run:   docker run --rm -v "$PWD:/work" -w /work sbom-fixer:1.0.0 fix build/sbom.json --out build/sbom-fixed
# The build needs no network for sbomqs: it uses the archive vendored in tools/sbomqs (tools/vendor_sbomqs.py)
# and checks it against tools/sbomqs/SHA256SUMS. Keep SBOMQS_VERSION equal to tools/sbomqs/VERSION.
FROM python:3.12-slim

ARG SBOMQS_VERSION=2.1.2

WORKDIR /opt/sbom-fixer
COPY tools/sbomqs/SHA256SUMS tools/sbomqs/LICENSE /opt/sbomqs/
COPY tools/sbomqs/linux-amd64/sbomqs_${SBOMQS_VERSION}_Linux_x86_64.tar.gz /opt/sbomqs/linux-amd64/
RUN cd /opt/sbomqs \
 && grep " linux-amd64/sbomqs_${SBOMQS_VERSION}_Linux_x86_64.tar.gz$" SHA256SUMS | sha256sum -c - \
 && tar -xzf linux-amd64/sbomqs_${SBOMQS_VERSION}_Linux_x86_64.tar.gz -C /usr/local/bin sbomqs \
 && chmod +x /usr/local/bin/sbomqs \
 && rm -rf linux-amd64 \
 && sbomqs version

COPY pyproject.toml README.md ./
COPY sbom_fixer ./sbom_fixer
RUN pip install --no-cache-dir . && useradd --create-home fixer

USER fixer
ENTRYPOINT ["sbom-fixer"]
CMD ["--help"]
