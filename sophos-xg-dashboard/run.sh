#!/usr/bin/with-contenv sh
set -eu

echo "[Sophos XG Dashboard] Starting add-on"
exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --proxy-headers \
  --forwarded-allow-ips="*"
