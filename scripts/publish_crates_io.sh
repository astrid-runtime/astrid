#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: publish_crates_io.sh <version> <release-source-root>" >&2
  exit 2
fi

version=$1
source_root=$2
work_root=${RUNNER_TEMP:?RUNNER_TEMP must be set by the protected release runner}
script_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
[[ -n "${CARGO_REGISTRY_TOKEN:-}" ]]
[[ -f "$source_root/Cargo.toml" && ! -L "$source_root/Cargo.toml" ]]

(
  cd "$source_root"
  cargo metadata --no-deps --format-version 1 > "$work_root/cargo-metadata.json"
)
python3 "$script_root/crate_publication.py" \
  --metadata "$work_root/cargo-metadata.json" \
  --version "$version" > "$work_root/crates.txt"
[[ "$(wc -l < "$work_root/crates.txt")" == 26 ]]

crates_io_version() {
  local crate=$1
  local output=$2
  curl --silent --show-error \
    --user-agent 'astrid-stable-promotion (https://github.com/astrid-runtime/astrid)' \
    --output "$output" \
    --write-out '%{http_code}' \
    "https://crates.io/api/v1/crates/${crate}/${version}"
}

verify_crates_io_version() {
  local crate=$1
  local response=$2
  local expected=$3
  jq -e --arg expected "$expected" \
    '.version.checksum == $expected and .version.yanked == false' \
    "$response" >/dev/null || {
    echo "crates.io has an unusable or byte-different ${crate}@${version}" >&2
    return 1
  }
}

while IFS= read -r crate; do
  packaged=0
  for _ in {1..60}; do
    if (cd "$source_root" && cargo package --locked --no-verify -p "$crate"); then
      packaged=1
      break
    fi
    sleep 5
  done
  [[ "$packaged" == 1 ]] || {
    echo "could not package ${crate}@${version} from the crates.io dependency graph" >&2
    exit 1
  }

  archive="$source_root/target/package/${crate}-${version}.crate"
  expected=$(sha256sum -- "$archive" | awk '{print $1}')
  response="$work_root/crates-io-${crate}.json"
  status=$(crates_io_version "$crate" "$response")
  case "$status" in
    200)
      verify_crates_io_version "$crate" "$response" "$expected"
      continue
      ;;
    404) ;;
    *)
      echo "crates.io returned HTTP $status for ${crate}@${version}" >&2
      exit 1
      ;;
  esac

  published=0
  for _ in {1..60}; do
    (cd "$source_root" && cargo publish --locked -p "$crate") || true
    status=$(crates_io_version "$crate" "$response")
    if [[ "$status" == 200 ]]; then
      verify_crates_io_version "$crate" "$response" "$expected"
      published=1
      break
    fi
    [[ "$status" == 404 ]] || {
      echo "crates.io returned HTTP $status for ${crate}@${version}" >&2
      exit 1
    }
    sleep 5
  done
  [[ "$published" == 1 ]] || {
    echo "${crate}@${version} did not become available on crates.io" >&2
    exit 1
  }
done < "$work_root/crates.txt"
