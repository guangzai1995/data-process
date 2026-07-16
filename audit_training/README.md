# Audit Training Outputs

This directory is the default output root for `scripts/audit_training_pipeline.py`.

Generated files are ignored by Git by default. Keep only this README under version control.

Daily run:

```bash
python3 scripts/audit_training_pipeline.py --yesterday
```

Backfill:

```bash
python3 scripts/audit_training_pipeline.py --start-date 2026-07-01 --end-date 2026-07-15
```

Validation run:

```bash
python3 scripts/audit_training_pipeline.py --date 2026-07-15 --limit 100 --dry-run
```

Optional labeler environment:

```text
AUDIT_LABEL_BASE_URL
AUDIT_LABEL_API_KEY
AUDIT_LABEL_MODEL
AUDIT_LABEL_TIMEOUT
AUDIT_LABEL_MAX_CONCURRENCY
```
