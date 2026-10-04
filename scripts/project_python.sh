#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -x /opt/dftexp_scan/bin/dftexp_scan ]]; then
    interpreter=/usr/bin/python3
else
    interpreter="$project_root/.venv/bin/python"
fi
if [[ ! -x "$interpreter" ]]; then
    echo 'Create .venv and install requirements-dev.txt first.' >&2
    exit 1
fi
exec "$interpreter" "$@"
