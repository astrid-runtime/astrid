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
  status="$(http_status GET /api/sys/capabilities "$bearer" "" "$ARTIFACTS/$label-capabilities.json")"
  assert_status "$label capability catalog" "$status" 200
  json_assert_capability_catalog "$ARTIFACTS/$label-capabilities.json"
  status="$(http_status GET /api/capsules/astrid-capsule-registry/topics "$bearer" "" \
    "$ARTIFACTS/$label-registry-topics.json")"
  assert_status "$label capsule topics" "$status" 200
  json_assert_capsule_topics_shape "$ARTIFACTS/$label-registry-topics.json"
  status="$(http_status GET /api/events "" "" "$ARTIFACTS/unauth-events.json")"
  assert_status "unauthenticated events denied" "$status" 401
  assert_events_ready "$label" "$bearer"
}

run_gateway_quota_write_smoke() {
  local user_principal=$1 ops_principal=$2 user_bearer=$3 admin_bearer=$4 status body
  status="$(http_status GET "/api/sys/principals/$user_principal/quotas" "$admin_bearer" "" \
    "$ARTIFACTS/http-quota-before-write.json")"
  assert_status "admin quota read before write" "$status" 200
  body="$(quota_request_body "$ARTIFACTS/http-quota-before-write.json" 5)"
  status="$(http_status PUT "/api/sys/principals/$user_principal/quotas" "$admin_bearer" "$body" \
    "$ARTIFACTS/http-quota-write.json")"
  assert_status "admin quota write" "$status" 200
  status="$(http_status GET "/api/sys/principals/$user_principal/quotas" "$user_bearer" "" \
    "$ARTIFACTS/http-quota-after-write.json")"
  assert_status "agent quota read after HTTP write" "$status" 200
  json_assert_field_equals "$ARTIFACTS/http-quota-after-write.json" max_background_processes 5
  body="$(quota_request_body "$ARTIFACTS/http-quota-after-write.json" 6)"
  status="$(http_status PUT "/api/sys/principals/$user_principal/quotas" "$user_bearer" "$body" \
    "$ARTIFACTS/http-quota-self-write.json")"
  assert_status "agent quota self-write" "$status" 200
  status="$(http_status GET "/api/sys/principals/$user_principal/quotas" "$user_bearer" "" \
    "$ARTIFACTS/http-quota-after-self-write.json")"
  assert_status "agent quota read after self-write" "$status" 200
  json_assert_field_equals "$ARTIFACTS/http-quota-after-self-write.json" max_background_processes 6
  status="$(http_status PUT "/api/sys/principals/$ops_principal/quotas" "$user_bearer" "$body" \
    "$ARTIFACTS/http-quota-cross-principal-write-denied.json")"
  assert_status "agent cross-principal quota write denied" "$status" 403
  status="$(http_status GET "/api/sys/principals/$user_principal/usage" "$user_bearer" "" \
    "$ARTIFACTS/http-usage-self.json")"
  assert_status "agent usage self-read" "$status" 200
  json_assert_usage_principal "$ARTIFACTS/http-usage-self.json" "$user_principal"
  status="$(http_status GET "/api/sys/principals/$ops_principal/usage" "$user_bearer" "" \
    "$ARTIFACTS/http-usage-cross-principal-denied.json")"
  assert_status "agent cross-principal usage denied" "$status" 403
  body="$(quota_request_body "$ARTIFACTS/http-quota-after-write.json" 4)"
  status="$(http_status PUT "/api/sys/principals/$user_principal/quotas" "$admin_bearer" "$body" \
    "$ARTIFACTS/http-quota-restore.json")"
  assert_status "admin quota restore" "$status" 200
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

json_assert_capability_catalog() {
  local file=$1
  "$PYTHON" - "$file" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
ids = {entry.get("id") for entry in data.get("capabilities", [])}
for capability in ("system:status", "capsule:install", "self:capsule:list"):
    if capability not in ids:
        raise SystemExit(f"capability catalog missing {capability!r}: {sorted(ids)!r}")
for category in ("agent", "capsule", "system"):
    if category not in data.get("categories", []):
        raise SystemExit(f"capability categories missing {category!r}: {data!r}")
PY
}

json_assert_capsule_topics_shape() {
  local file=$1
  "$PYTHON" - "$file" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
topics = data.get("topics")
if not isinstance(topics, list):
    raise SystemExit(f"capsule topics response missed topics array: {data!r}")
PY
}

json_assert_usage_principal() {
  local file=$1 principal=$2
  "$PYTHON" - "$file" "$principal" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("principal") != sys.argv[2]:
    raise SystemExit(f"unexpected usage principal: {data!r}")
for key in ("cpu_fuel_consumed_total", "cpu_fuel_per_sec_limit", "exempt"):
    if key not in data:
        raise SystemExit(f"usage response missed {key}: {data!r}")
PY
}

quota_request_body() {
  local file=$1 processes=$2
  "$PYTHON" - "$file" "$processes" <<'PY'
import json
import sys

quotas = json.load(open(sys.argv[1], encoding="utf-8"))
quotas["max_background_processes"] = int(sys.argv[2])
print(json.dumps({"quotas": quotas}, separators=(",", ":")))
PY
}

assert_events_ready() {
  local label=$1 bearer=$2 status curl_status headers out
  headers="$ARTIFACTS/$label-events.headers"
  out="$ARTIFACTS/$label-events.sse"
  set +e
  status="$(curl --connect-timeout 2 --max-time 3 -sS -N -D "$headers" -o "$out" \
    -w "%{http_code}" -H "Authorization: Bearer $bearer" "$GATEWAY/api/events")"
  curl_status=$?
  set -e
  [[ "$status" == "200" ]] || fail "$label events expected HTTP 200, got $status"
  [[ "$curl_status" -eq 0 || "$curl_status" -eq 28 ]] \
    || fail "$label events curl exited $curl_status"
  grep -q '^event: ready' "$out" || fail "$label events stream missed ready event"
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
