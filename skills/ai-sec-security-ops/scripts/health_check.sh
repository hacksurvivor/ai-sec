#!/usr/bin/env bash
set -euo pipefail

base_url="${AI_SEC_GATEWAY_URL:-http://127.0.0.1:8080}"
exec curl -fsS "${base_url%/}/health"
