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
