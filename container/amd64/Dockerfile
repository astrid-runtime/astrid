FROM docker.io/library/ubuntu@sha256:52df9b1ee71626e0088f7d400d5c6b5f7bb916f8f0c82b474289a4ece6cf3faf

ARG ASTRID_VERSION
ARG ASTRID_SOURCE_COMMIT
ARG ASTRID_ARCHIVE_SHA256
ARG ASTRID_ARCHIVE_BLAKE3
ARG ASTRID_RELEASE_RECEIPT_SHA256
ARG ASTRID_RELEASE_MANIFEST_SHA256

LABEL org.opencontainers.image.title="Astrid Runtime" \
      org.opencontainers.image.description="Distro-neutral Astrid Runtime for Linux amd64" \
      org.opencontainers.image.source="https://github.com/astrid-runtime/astrid" \
      org.opencontainers.image.version="${ASTRID_VERSION}" \
      org.opencontainers.image.revision="${ASTRID_SOURCE_COMMIT}" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT" \
      io.astrid.release.target="x86_64-unknown-linux-gnu" \
      io.astrid.release.archive-sha256="${ASTRID_ARCHIVE_SHA256}" \
      io.astrid.release.archive-blake3="${ASTRID_ARCHIVE_BLAKE3}" \
      io.astrid.release.receipt-sha256="${ASTRID_RELEASE_RECEIPT_SHA256}" \
      io.astrid.release.manifest-sha256="${ASTRID_RELEASE_MANIFEST_SHA256}"

COPY dist/oci-amd64/astrid-release.tar.gz /tmp/astrid-release.tar.gz
COPY dist/oci-amd64/release-receipt.json /opt/astrid/release-receipt.json
COPY container/amd64/entrypoint.sh /usr/local/bin/astrid-container-entrypoint

RUN set -eu; \
    test -n "$ASTRID_VERSION"; \
    test -n "$ASTRID_SOURCE_COMMIT"; \
    case "$ASTRID_SOURCE_COMMIT" in *[!0-9a-f]*|'') exit 1 ;; esac; \
    test "${#ASTRID_SOURCE_COMMIT}" -eq 40; \
    case "$ASTRID_ARCHIVE_SHA256" in *[!0-9a-f]*|'') exit 1 ;; esac; \
    test "${#ASTRID_ARCHIVE_SHA256}" -eq 64; \
    case "$ASTRID_ARCHIVE_BLAKE3" in *[!0-9a-f]*|'') exit 1 ;; esac; \
    test "${#ASTRID_ARCHIVE_BLAKE3}" -eq 64; \
    case "$ASTRID_RELEASE_RECEIPT_SHA256" in *[!0-9a-f]*|'') exit 1 ;; esac; \
    test "${#ASTRID_RELEASE_RECEIPT_SHA256}" -eq 64; \
    case "$ASTRID_RELEASE_MANIFEST_SHA256" in *[!0-9a-f]*|'') exit 1 ;; esac; \
    test "${#ASTRID_RELEASE_MANIFEST_SHA256}" -eq 64; \
    echo "$ASTRID_ARCHIVE_SHA256  /tmp/astrid-release.tar.gz" | sha256sum --check --strict -; \
    echo "$ASTRID_RELEASE_RECEIPT_SHA256  /opt/astrid/release-receipt.json" | sha256sum --check --strict -; \
    bind_receipt_field() { \
      actual=$(sed -nE "s/^[[:space:]]*\"$2\"[[:space:]]*:[[:space:]]*\"([^\"]*)\",?$/\1/p" "$1"); \
      [ "$actual" = "$3" ]; \
    }; \
    bind_receipt_field /opt/astrid/release-receipt.json \
      "repository" "astrid-runtime/astrid"; \
    bind_receipt_field /opt/astrid/release-receipt.json \
      "version" "$ASTRID_VERSION"; \
    bind_receipt_field /opt/astrid/release-receipt.json \
      "tag" "v$ASTRID_VERSION"; \
    bind_receipt_field /opt/astrid/release-receipt.json \
      "source-commit" "$ASTRID_SOURCE_COMMIT"; \
    bind_receipt_field /opt/astrid/release-receipt.json \
      "target" "x86_64-unknown-linux-gnu"; \
    bind_receipt_field /opt/astrid/release-receipt.json \
      "archive" "astrid-$ASTRID_VERSION-x86_64-unknown-linux-gnu.tar.gz"; \
    bind_receipt_field /opt/astrid/release-receipt.json \
      "archive-sha256" "$ASTRID_ARCHIVE_SHA256"; \
    bind_receipt_field /opt/astrid/release-receipt.json \
      "archive-blake3" "$ASTRID_ARCHIVE_BLAKE3"; \
    bind_receipt_field /opt/astrid/release-receipt.json \
      "release-manifest" "astrid-$ASTRID_VERSION-release.toml"; \
    bind_receipt_field /opt/astrid/release-receipt.json \
      "release-manifest-sha256" "$ASTRID_RELEASE_MANIFEST_SHA256"; \
    bind_receipt_field /opt/astrid/release-receipt.json \
      "release-workflow-identity" "https://github.com/astrid-runtime/astrid/.github/workflows/release.yml@refs/tags/v$ASTRID_VERSION"; \
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
