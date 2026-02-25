#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "${script_dir}/policy.default.yaml" "${script_dir}/policy.yaml"
echo "Applied policy profile: default (policy.default.yaml -> policy.yaml)"
