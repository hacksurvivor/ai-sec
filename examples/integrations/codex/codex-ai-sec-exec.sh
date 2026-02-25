#!/usr/bin/env bash
# Bash 3.x on macOS treats empty arrays as unbound under `set -u`.
# Keep strict error/pipe handling while staying compatible with default shells.
set -eo pipefail

print_help() {
  cat <<'EOF'
Usage:
  codex-ai-sec-exec --prompt "..." [--tool <name> ...] [--confirmed-tool <name> ...] [-- <codex exec args...>]
  echo "..." | codex-ai-sec-exec --stdin [--tool terminal.exec]

Exit codes:
  0   allow/sanitize
  20  challenge/human_review
  30  block/fail/quarantine
  1   error
EOF
}

prompt=""
read_from_stdin=0
declare -a requested_tools=()
declare -a confirmed_tools=()
declare -a codex_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      print_help
      exit 0
      ;;
    --prompt)
      prompt="${2:-}"
      shift 2
      ;;
    --stdin)
      read_from_stdin=1
      shift
      ;;
    --tool)
      requested_tools+=("${2:-}")
      shift 2
      ;;
    --confirmed-tool)
      confirmed_tools+=("${2:-}")
      shift 2
      ;;
    --)
      shift
      codex_args+=("$@")
      break
      ;;
    *)
      if [[ -z "$prompt" ]]; then
        prompt="$1"
      else
        codex_args+=("$1")
      fi
      shift
      ;;
  esac
done

if [[ "$read_from_stdin" -eq 1 || ( -z "$prompt" && ! -t 0 ) ]]; then
  prompt="$(cat)"
fi

if [[ -z "${prompt//[$' \t\r\n']/}" ]]; then
  echo "codex-ai-sec-exec: prompt is required" >&2
  exit 1
fi

if [[ -n "${AI_SEC_CONFIRMED_TOOLS:-}" ]]; then
  declare -a env_confirmed=()
  IFS=',' read -r -a env_confirmed <<< "$AI_SEC_CONFIRMED_TOOLS"
  for tool in "${env_confirmed[@]}"; do
    cleaned="$(echo "$tool" | xargs)"
    if [[ -n "$cleaned" ]]; then
      confirmed_tools+=("$cleaned")
    fi
  done
fi

gate_cmd=(
  ai-sec agent gate
  --prompt "$prompt"
  --session-id "${AI_SEC_SESSION_ID:-sess_codex_guard}"
  --user-id "${AI_SEC_USER_ID:-codex_user}"
  --pretty
)

if [[ -n "${AI_SEC_GATEWAY_URL:-}" ]]; then
  gate_cmd+=(--base-url "$AI_SEC_GATEWAY_URL")
fi

token="${AI_SEC_BEARER_TOKEN:-${SERVICE_API_TOKEN:-}}"
if [[ -n "$token" ]]; then
  gate_cmd+=(--token "$token")
fi

for tool in "${requested_tools[@]}"; do
  gate_cmd+=(--tool "$tool")
done

for tool in "${confirmed_tools[@]}"; do
  gate_cmd+=(--confirmed-tool "$tool")
done

set +e
gate_output="$("${gate_cmd[@]}" 2>&1)"
gate_code=$?
set -e

if [[ "$gate_code" -ne 0 ]]; then
  echo "$gate_output" >&2
  exit "$gate_code"
fi

if [[ -n "$gate_output" ]]; then
  echo "$gate_output"
fi

exec codex exec "$prompt" "${codex_args[@]}"
