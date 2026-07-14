#!/usr/bin/env bash
# Print one effective Docker Compose host port without sourcing .env.
# Usage: ./scripts/resolve-host-port.sh VEDETTA_BACKEND_PORT 8080 [dotenv-file]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=scripts/lib/port-config.sh
source "${SCRIPT_DIR}/lib/port-config.sh"

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 <VEDETTA_*_PORT> <default> [dotenv-file]" >&2
  exit 2
fi

port="$(vedetta_resolve_port "$1" "$2" "${3:-${REPO_ROOT}/.env}")"
printf '%s\n' "${port}"
