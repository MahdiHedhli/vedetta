#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 -I "$script_dir/check_repo_sanitization.py" "$@"
