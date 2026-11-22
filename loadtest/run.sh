#!/usr/bin/env bash
# Boot the API (2 uvicorn workers) against a moto S3 server, run the k6 load test, tear down.
#
# Needs: uv, Docker (for the grafana/k6 image), and a migrated Postgres + a Redis reachable
# at DATABASE_URL / REDIS_URL. Used by CI and for local runs:
#
#   DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/fileshare_load \
#   REDIS_URL=redis://localhost:6379/5 loadtest/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."

: "${DATABASE_URL:?set DATABASE_URL}"
: "${REDIS_URL:?set REDIS_URL}"
S3_PORT="${S3_PORT:-5055}"
API_PORT="${API_PORT:-8000}"
K6_IMAGE="${K6_IMAGE:-grafana/k6:0.54.0}"

export ENVIRONMENT=development LOG_LEVEL=WARNING DB_POOL_SIZE=20 SMTP_HOST=
# Simulated clients send their own X-Forwarded-For; setup uploads without reading email.
export TRUST_PROXY_HEADERS=true REQUIRE_VERIFIED_EMAIL=false
export S3_ENDPOINT_URL="http://127.0.0.1:${S3_PORT}" S3_PUBLIC_ENDPOINT_URL="http://127.0.0.1:${S3_PORT}"
export S3_BUCKET=fileshare S3_ACCESS_KEY_ID=test S3_SECRET_ACCESS_KEY=test S3_CREATE_BUCKET=true

logs="$(mktemp -d)"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

uv run alembic upgrade head
uv run python -m moto.server -p "$S3_PORT" >"$logs/moto.log" 2>&1 &
pids+=($!)
sleep 2
uv run uvicorn app.main:app_factory --factory --port "$API_PORT" --workers 2 >"$logs/api.log" 2>&1 &
pids+=($!)

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${API_PORT}/readyz" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${API_PORT}/readyz" >/dev/null || { cat "$logs/api.log"; exit 1; }

status=0
docker run --rm --network host -v "$PWD/loadtest:/loadtest:ro" \
  -e BASE_URL="http://127.0.0.1:${API_PORT}" "$K6_IMAGE" run --quiet /loadtest/k6/security-under-load.js || status=$?

if grep -q '" 500 ' "$logs/api.log"; then
  echo "API logged 500 responses:" >&2
  grep '" 500 ' "$logs/api.log" | head -20 >&2
  status=1
fi
exit "$status"
