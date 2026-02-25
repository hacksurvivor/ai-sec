#!/usr/bin/env bash
set -euo pipefail

# Generic prompt/tool gate for coding agents.
# Usage:
#   ./examples/agent-guard.sh "Prompt text" terminal.exec write_file
#   echo "Prompt text" | ./examples/agent-guard.sh "" terminal.exec

prompt="${1:-}"
shift || true

if [[ -z "$prompt" ]]; then
  prompt="$(cat)"
fi

if [[ -z "${prompt// }" ]]; then
  echo '{"status":"error","error":"empty prompt"}' >&2
  exit 1
fi

tool_args=()
for tool in "$@"; do
  tool_args+=(--tool "$tool")
done

if [[ -n "${AI_SEC_CONFIRMED_TOOLS:-}" ]]; then
  IFS=',' read -r -a confirmed_tools <<< "$AI_SEC_CONFIRMED_TOOLS"
  for tool in "${confirmed_tools[@]}"; do
    trimmed="$(echo "$tool" | xargs)"
    if [[ -n "$trimmed" ]]; then
      tool_args+=(--confirmed-tool "$trimmed")
    fi
  done
fi

set +e
result="$(printf "%s" "$prompt" | ai-sec agent gate --stdin "${tool_args[@]}" --pretty)"
code=$?
set -e

echo "$result"
exit "$code"
