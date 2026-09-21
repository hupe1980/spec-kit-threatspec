#!/usr/bin/env bash
# ThreatSpec wrapper: locates a Python runtime with PyYAML and delegates to the engine.
# Usage: threatspec.sh <subcommand> [args...]   (see scripts/python/threatspec.py --help)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE="$SCRIPT_DIR/../python/threatspec.py"

if [[ ! -f "$ENGINE" ]]; then
  echo "threatspec: engine not found at $ENGINE" >&2
  exit 2
fi

run_with() { exec "$@" "$ENGINE" "${ARGS[@]}"; }
ARGS=("$@")

# 1. A python3 that already has PyYAML
for py in python3 python; do
  if command -v "$py" >/dev/null 2>&1 && "$py" -c "import yaml" >/dev/null 2>&1; then
    run_with "$py"
  fi
done

# 2. uv with ephemeral dependencies (jsonschema enables full schema validation)
if command -v uv >/dev/null 2>&1; then
  run_with uv run --quiet --with pyyaml --with jsonschema python
fi

echo "threatspec: no Python runtime with PyYAML found. Install PyYAML (pip install pyyaml) or uv (https://docs.astral.sh/uv/)." >&2
exit 2
