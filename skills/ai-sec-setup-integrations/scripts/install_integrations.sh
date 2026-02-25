#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"

install_claude=1
install_codex=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --claude-only)
      install_codex=0
      ;;
    --codex-only)
      install_claude=0
      ;;
    --help|-h)
      cat <<'USAGE'
Usage: install_integrations.sh [--claude-only | --codex-only]
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
  shift
done

if [[ "$install_claude" -eq 1 ]]; then
  bash "${repo_root}/examples/integrations/claude/install.sh"
fi

if [[ "$install_codex" -eq 1 ]]; then
  bash "${repo_root}/examples/integrations/codex/install.sh"
fi

cat <<'EOF'
Integration setup complete.

Set env vars in your shell profile (example ~/.zshrc):
  export AI_SEC_GATEWAY_URL="http://127.0.0.1:8080"
  export AI_SEC_BEARER_TOKEN="token-analyst"

Optional strict mode:
  export AI_SEC_FAIL_CLOSED=1
EOF
