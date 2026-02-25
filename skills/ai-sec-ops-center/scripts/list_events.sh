#!/usr/bin/env bash
set -euo pipefail

limit="${1:-20}"
base_url="${AI_SEC_GATEWAY_URL:-http://127.0.0.1:8080}"
url="${base_url%/}/v1/security-events?limit=${limit}"
token="${AI_SEC_BEARER_TOKEN:-${SERVICE_API_TOKEN:-}}"

if [[ -n "$token" ]]; then
  exec curl -fsS "$url" -H "authorization: Bearer $token"
fi

exec curl -fsS "$url"
