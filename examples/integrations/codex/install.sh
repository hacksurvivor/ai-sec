#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${HOME}/.local/bin"
TARGET_FILE="${TARGET_DIR}/codex-ai-sec"

mkdir -p "${TARGET_DIR}"
cp "${SCRIPT_DIR}/codex-ai-sec-exec.sh" "${TARGET_FILE}"
chmod +x "${TARGET_FILE}"

cat <<EOF
Installed Codex guarded wrapper:
  ${TARGET_FILE}

Run with:
  codex-ai-sec --prompt "Implement this feature safely" --tool terminal.exec

Set env vars:
  export AI_SEC_GATEWAY_URL="http://127.0.0.1:8080"
  export AI_SEC_BEARER_TOKEN="token-analyst"
EOF

if [[ ":${PATH}:" != *":${TARGET_DIR}:"* ]]; then
  cat <<'EOF'

PATH note:
  ~/.local/bin is not currently on PATH in this shell.
  Add this line to ~/.zshrc:
    export PATH="$HOME/.local/bin:$PATH"
EOF
fi
