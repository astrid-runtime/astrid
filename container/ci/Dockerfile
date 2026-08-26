FROM rust:1.95.0-bookworm@sha256:4c2fd73ef19c5ef9d54bee03b06b2839a392604fbfcd578ed948b71b37c1d7fb

ARG ASTRID_SOURCE_COMMIT

LABEL org.opencontainers.image.title="Astrid CI toolchain"
LABEL org.opencontainers.image.description="CI-only Rust toolchain and Astrid binaries for capsule repositories"
LABEL org.opencontainers.image.source="https://github.com/astrid-runtime/astrid"
LABEL org.opencontainers.image.revision="${ASTRID_SOURCE_COMMIT}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV CARGO_TERM_COLOR=always
ENV RUST_BACKTRACE=1

RUN rustup target add wasm32-unknown-unknown \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        gh \
        jq \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 dist/ci/astrid /usr/local/bin/astrid
COPY --chmod=0755 dist/ci/astrid-build /usr/local/bin/astrid-build
COPY --chmod=0755 dist/ci/astrid-daemon /usr/local/bin/astrid-daemon
COPY --chmod=0755 dist/ci/astrid-emit /usr/local/bin/astrid-emit

RUN rustc --version | grep -Fq 'rustc 1.95.0 ' \
    && rustup target list --installed | grep -Fxq wasm32-unknown-unknown \
    && astrid --version \
    && astrid-build --version \
    && astrid-daemon --version \
    && astrid-emit --version

WORKDIR /github/workspace
