#!/usr/bin/env bash
set -euo pipefail

model="${1:-mock-model}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"

cd "$repo_root"
exec npm run redteam -- --suite prompt_injection_core --target-model "$model"
