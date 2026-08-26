#!/usr/bin/env bash
set -euo pipefail

IMAGE=${1:?usage: test.sh IMAGE VERSION SOURCE_COMMIT}
VERSION=${2:?usage: test.sh IMAGE VERSION SOURCE_COMMIT}
SOURCE_COMMIT=${3:?usage: test.sh IMAGE VERSION SOURCE_COMMIT}

revision=$(docker image inspect "$IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
test "$revision" = "$SOURCE_COMMIT"
version=$(docker image inspect "$IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.version"}}')
test "$version" = "$VERSION"
test "$(docker image inspect "$IMAGE" --format '{{json .Config.Entrypoint}}')" = null

docker run --rm "$IMAGE" bash -euc '
  rustc --version | grep -Fq "rustc 1.95.0 "
  cargo --version
  rustup target list --installed | grep -Fxq wasm32-unknown-unknown
  for command in astrid astrid-build astrid-daemon astrid-emit gh jq python3 git; do
    command -v "$command" >/dev/null
  done
  astrid --version
  astrid-build --version
  astrid-daemon --version
  astrid-emit --version
'
