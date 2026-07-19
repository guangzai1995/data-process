#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

if [ "$#" -eq 0 ]; then
  set -- --yesterday
fi

export PYTHONDONTWRITEBYTECODE=1
exec python3 scripts/audit_training_pipeline.py "$@"
