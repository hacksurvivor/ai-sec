#!/usr/bin/env bash
set -eo pipefail

prompt="${1:-}"
shift || true

if [[ -z "${prompt//[$' \t\r\n']/}" && ! -t 0 ]]; then
  prompt="$(cat)"
fi

if [[ -z "${prompt//[$' \t\r\n']/}" ]]; then
  echo "ai-sec-gatekeeper: prompt is required" >&2
  echo "usage: gate_prompt.sh \"<prompt>\" [tool ...]" >&2
  exit 1
fi

declare -a cmd=(
  ai-sec agent gate
  --prompt "$prompt"
  --session-id "${AI_SEC_SESSION_ID:-sess_skill_agent_guard}"
  --user-id "${AI_SEC_USER_ID:-skill_agent_user}"
  --pretty
)

if [[ -n "${AI_SEC_GATEWAY_URL:-}" ]]; then
  cmd+=(--base-url "$AI_SEC_GATEWAY_URL")
fi

token="${AI_SEC_BEARER_TOKEN:-${SERVICE_API_TOKEN:-}}"
if [[ -n "$token" ]]; then
  cmd+=(--token "$token")
fi

for tool in "$@"; do
  if [[ -n "${tool//[$' \t\r\n']/}" ]]; then
    cmd+=(--tool "$tool")
  fi
done

if [[ -n "${AI_SEC_CONFIRMED_TOOLS:-}" ]]; then
  IFS=',' read -r -a confirmed_tools <<< "$AI_SEC_CONFIRMED_TOOLS"
  for tool in "${confirmed_tools[@]}"; do
    trimmed="$(echo "$tool" | xargs)"
    if [[ -n "$trimmed" ]]; then
      cmd+=(--confirmed-tool "$trimmed")
    fi
  done
fi

"${cmd[@]}"
