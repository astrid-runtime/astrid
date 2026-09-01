#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/publish_crates_io.sh
source "$repo_root/scripts/publish_crates_io.sh"

for padded_count in '29' ' 29' '29 ' ' 29 '; do
  count=$(printf '%s\n' "$padded_count" | parse_wc_l_count)
  [[ "$count" == 29 ]] || {
    echo "expected padded count '$padded_count' to parse as 29, found '$count'" >&2
    exit 1
  }
done

for invalid_count in '' ' 2 9' 'twenty-nine' '-1'; do
  if printf '%s\n' "$invalid_count" | parse_wc_l_count >/dev/null 2>&1; then
    echo "expected invalid count '$invalid_count' to be rejected" >&2
    exit 1
  fi
done
