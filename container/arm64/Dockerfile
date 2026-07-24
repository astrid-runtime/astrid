FROM docker.io/library/ubuntu@sha256:7f622ca8766bccb22f04242ecb6f19f770b2f08827dc4b8c707de5e78a6da7ab

ARG ASTRID_VERSION
ARG ASTRID_SOURCE_COMMIT
ARG ASTRID_ARCHIVE_SHA256

LABEL org.opencontainers.image.title="Astrid Runtime" \
      org.opencontainers.image.description="Distro-neutral Astrid Runtime for Linux arm64" \
      org.opencontainers.image.source="https://github.com/astrid-runtime/astrid" \
      org.opencontainers.image.version="${ASTRID_VERSION}" \
      org.opencontainers.image.revision="${ASTRID_SOURCE_COMMIT}" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT" \
      io.astrid.release.target="aarch64-unknown-linux-gnu"

COPY dist/oci-arm64/astrid-release.tar.gz /tmp/astrid-release.tar.gz
COPY dist/oci-arm64/release-receipt.json /opt/astrid/release-receipt.json
COPY container/amd64/entrypoint.sh /usr/local/bin/astrid-container-entrypoint

RUN set -eu; \
    test -n "$ASTRID_VERSION"; \
    test -n "$ASTRID_SOURCE_COMMIT"; \
    case "$ASTRID_SOURCE_COMMIT" in *[!0-9a-f]*|'') exit 1 ;; esac; \
    test "${#ASTRID_SOURCE_COMMIT}" -eq 40; \
    case "$ASTRID_ARCHIVE_SHA256" in *[!0-9a-f]*|'') exit 1 ;; esac; \
    test "${#ASTRID_ARCHIVE_SHA256}" -eq 64; \
    echo "$ASTRID_ARCHIVE_SHA256  /tmp/astrid-release.tar.gz" | sha256sum --check --strict -; \
    mkdir -p /opt/astrid/release /var/lib/astrid /workspace /run/astrid; \
    tar -xzf /tmp/astrid-release.tar.gz \
      --strip-components=1 \
      --directory /opt/astrid/release; \
    for binary in astrid astrid-daemon astrid-build astrid-emit; do \
      test -x "/opt/astrid/release/$binary"; \
      ln -s "/opt/astrid/release/$binary" "/usr/local/bin/$binary"; \
    done; \
    rm /tmp/astrid-release.tar.gz; \
    /usr/sbin/groupadd --gid 65532 astrid; \
    /usr/sbin/useradd \
      --uid 65532 \
      --gid 65532 \
      --home-dir /var/lib/astrid \
      --no-create-home \
      --shell /usr/sbin/nologin \
      astrid; \
    chown -R 65532:65532 /var/lib/astrid /workspace; \
    chmod 0555 /usr/local/bin/astrid-container-entrypoint; \
    chmod -R go-w /opt/astrid

ENV ASTRID_HOME=/var/lib/astrid \
    ASTRID_WORKSPACE=/workspace \
    ASTRID_DAEMON_LOG_TARGET=stderr \
    HOME=/var/lib/astrid

VOLUME ["/var/lib/astrid", "/workspace"]
WORKDIR /workspace
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/astrid-container-entrypoint"]
