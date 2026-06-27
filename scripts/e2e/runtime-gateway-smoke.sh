#!/usr/bin/env bash

run_gateway_public_surface_smoke() {
  local status
  status="$(http_status GET /api/distribution "" "" "$ARTIFACTS/public-distribution.json")"
  assert_status "public distribution" "$status" 200
  status="$(http_status GET /api/distribution/onboarding "" "" "$ARTIFACTS/public-onboarding.json")"
  assert_status "public distribution onboarding" "$status" 200
  status="$(http_status GET /api/openapi.json "" "" "$ARTIFACTS/public-openapi.json")"
  assert_status "public openapi" "$status" 200
  status="$(http_status GET /metrics "" "" "$ARTIFACTS/public-metrics.txt")"
  assert_status "public metrics" "$status" 200
  json_assert_public_gateway_surface \
    "$ARTIFACTS/public-distribution.json" \
    "$ARTIFACTS/public-onboarding.json" \
    "$ARTIFACTS/public-openapi.json" \
    "$ARTIFACTS/public-metrics.txt"
  json_assert_metrics_contract "$ARTIFACTS/public-metrics.txt"
}

run_gateway_principal_surface_smoke() {
  local label=$1 bearer=$2 reload_status=$3 status
  status="$(http_status GET /api/sys/readiness "$bearer" "" "$ARTIFACTS/$label-readiness.json")"
  assert_status "$label readiness" "$status" 200
  json_assert_readiness_capsules_filtered "$ARTIFACTS/$label-readiness.json"
  status="$(http_status GET /api/sys/readiness "" "" "$ARTIFACTS/unauth-readiness.json")"
  assert_status "unauthenticated readiness denied" "$status" 401
  status="$(http_status POST /api/sys/capsules/reload "$bearer" "" "$ARTIFACTS/$label-reload-denied.json")"
  assert_status "$label reload" "$status" "$reload_status"
}

json_assert_public_gateway_surface() {
  local distribution=$1 onboarding=$2 openapi=$3 metrics=$4
  "$PYTHON" - "$distribution" "$onboarding" "$openapi" "$metrics" <<'PY'
import json
import sys

distribution = json.load(open(sys.argv[1], encoding="utf-8"))
if distribution.get("id") != "single-tenant":
    raise SystemExit(f"unexpected distribution id: {distribution!r}")
if distribution.get("name") != "Astrid":
    raise SystemExit(f"unexpected distribution name: {distribution!r}")
if distribution.get("invites_enabled") is not False:
    raise SystemExit(f"single-tenant distribution should not advertise invites: {distribution!r}")

onboarding = json.load(open(sys.argv[2], encoding="utf-8"))
if onboarding.get("fields") != []:
    raise SystemExit(f"single-tenant onboarding fields should be empty: {onboarding!r}")

openapi = json.load(open(sys.argv[3], encoding="utf-8"))
paths = openapi.get("paths", {})
required = {
    "/api/agent/prompt",
    "/api/distribution",
    "/api/sys/readiness",
    "/metrics",
}
missing = sorted(required.difference(paths))
if missing:
    raise SystemExit(f"openapi missing expected paths {missing!r}")

metrics = open(sys.argv[4], encoding="utf-8").read()
for needle in ("astrid_build_info", "astrid_gateway_requests_total"):
    if needle not in metrics:
        raise SystemExit(f"metrics scrape missing {needle!r}")
PY
}

json_assert_readiness_capsules_filtered() {
  local file=$1
  "$PYTHON" - "$file" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
loaded = data.get("loaded_capsules", [])
if "astrid-capsule-registry" not in loaded:
    raise SystemExit(f"readiness missed granted registry capsule: {loaded!r}")
if "astrid-capsule-cli" in loaded:
    raise SystemExit(f"readiness leaked default-only cli capsule: {loaded!r}")
PY
}

json_assert_metrics_contract() {
  local metrics=$1
  shift
  "$PYTHON" - "$metrics" "$@" <<'PY'
import re
import sys

metrics = open(sys.argv[1], encoding="utf-8").read()
for needle in (
    "astrid_build_info",
    "astrid_gateway_requests_total",
    "astrid_gateway_request_duration_seconds",
):
    if needle not in metrics:
        raise SystemExit(f"metrics scrape missing {needle!r}")

for forbidden in [s for s in sys.argv[2:] if s]:
    if forbidden in metrics:
        raise SystemExit(f"metrics scrape leaked dynamic identifier {forbidden!r}")

if "DO_NOT_LEAK" in metrics or "Authorization" in metrics or "session_token" in metrics:
    raise SystemExit("metrics scrape leaked sensitive marker or auth material")

uuidish = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
routes = set(re.findall(r'route="([^"]+)"', metrics))
for route in routes:
    if "?" in route:
        raise SystemExit(f"metrics route label includes query string: {route!r}")
    if uuidish.search(route):
        raise SystemExit(f"metrics route label includes concrete UUID: {route!r}")
    if route and not (route.startswith("/") or route.startswith("<")):
        raise SystemExit(f"metrics route label is not a route template: {route!r}")
PY
}
