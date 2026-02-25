#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_HOOK_DIR="${HOME}/.claude/hooks"
TARGET_HOOK="${TARGET_HOOK_DIR}/claude-ai-sec-hook.py"
SETTINGS_FILE="${HOME}/.claude/settings.json"

mkdir -p "${TARGET_HOOK_DIR}"
cp "${SCRIPT_DIR}/claude-ai-sec-hook.py" "${TARGET_HOOK}"
chmod +x "${TARGET_HOOK}"

python3 - <<'PY'
import json
import os
import shutil
from datetime import datetime
from pathlib import Path

settings_path = Path.home() / ".claude" / "settings.json"
settings_path.parent.mkdir(parents=True, exist_ok=True)

if settings_path.exists():
    backup = settings_path.with_name(f"settings.json.bak-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(settings_path, backup)
    raw = settings_path.read_text(encoding="utf-8")
    data = json.loads(raw) if raw.strip() else {}
else:
    data = {}

if not isinstance(data, dict):
    data = {}

hooks = data.setdefault("hooks", {})
if not isinstance(hooks, dict):
    hooks = {}
    data["hooks"] = hooks

command = 'python3 "$HOME/.claude/hooks/claude-ai-sec-hook.py"'

def contains_command(entries):
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for hook in entry.get("hooks", []):
            if isinstance(hook, dict) and hook.get("type") == "command" and hook.get("command") == command:
                return True
    return False

user_prompt_entries = hooks.setdefault("UserPromptSubmit", [])
if not contains_command(user_prompt_entries):
    user_prompt_entries.append(
        {
            "hooks": [
                {
                    "type": "command",
                    "command": command,
                }
            ]
        }
    )

pre_tool_entries = hooks.setdefault("PreToolUse", [])
if not contains_command(pre_tool_entries):
    pre_tool_entries.append(
        {
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": command,
                }
            ],
        }
    )

settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY

cat <<'EOF'
Installed Claude Code ai-sec hook:
  ~/.claude/hooks/claude-ai-sec-hook.py

Updated hook entries in:
  ~/.claude/settings.json

Set these env vars for hook runtime:
  export AI_SEC_GATEWAY_URL="http://127.0.0.1:8080"
  export AI_SEC_BEARER_TOKEN="token-analyst"

Optional:
  export AI_SEC_FAIL_CLOSED=1
EOF
