#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "${script_dir}/policy.strict.yaml" "${script_dir}/policy.yaml"
echo "Applied policy profile: strict (policy.strict.yaml -> policy.yaml)"
