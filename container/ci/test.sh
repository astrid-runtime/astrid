#!/usr/bin/env bash
set -euo pipefail

IMAGE=${1:?usage: test.sh IMAGE SOURCE_COMMIT}
SOURCE_COMMIT=${2:?usage: test.sh IMAGE SOURCE_COMMIT}

revision=$(docker image inspect "$IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
test "$revision" = "$SOURCE_COMMIT"
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
