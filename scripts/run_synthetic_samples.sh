#!/usr/bin/env sh
set -u

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR" || exit 1

on_interrupt() {
  echo "Interrupted. Progress is saved in audit_training/synthetic_samples/state.json" >&2
  echo "Run scripts/run_synthetic_samples.sh again with the same arguments to resume." >&2
  exit 130
}

trap on_interrupt INT TERM

PYTHONDONTWRITEBYTECODE=1 "${PYTHON:-python3}" \
  scripts/synthesize_training_samples.py \
  --env-file .env \
  "$@"

status=$?
if [ "$status" -eq 130 ]; then
  on_interrupt
fi
exit "$status"
