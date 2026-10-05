FROM ubuntu:24.04

COPY dist/tracey_*.deb /tmp/tracey/

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    arch="$(dpkg --print-architecture)"; \
    deb="$(find /tmp/tracey -maxdepth 1 -type f -name "tracey_*_${arch}.deb" | head -n 1)"; \
    test -n "$deb"; \
    apt-get install -y --no-install-recommends "$deb"; \
    rm -rf /tmp/tracey; \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["tracey"]
CMD ["--help"]

# OCI metadata (final stage) so GHCR links the package to its source repository.
LABEL org.opencontainers.image.source="https://github.com/neuralmimicry/tracey" \
      org.opencontainers.image.url="https://github.com/neuralmimicry/tracey" \
      org.opencontainers.image.description="Swarm anomaly/security runtime: fuzzy inference scoring, multi-agent consensus, fleet telemetry, TraceyGuard/TraceyBan" \
      org.opencontainers.image.vendor="NeuralMimicry"
