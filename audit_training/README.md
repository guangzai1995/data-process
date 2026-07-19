# Audit Training Outputs

This directory is the default output root for `scripts/audit_training_pipeline.py`.
Generated dataset files are ignored by Git by default. Keep only this README under version control.

## Runs

Daily run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_training_pipeline.py --yesterday
```

Backfill:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_training_pipeline.py --start-date 2026-07-01 --end-date 2026-07-15
```

Validation run without final outputs:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_training_pipeline.py --date 2026-07-15 --limit 100 --dry-run
```

Cron example:

```cron
15 2 * * * cd /path/to/repo && PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_training_pipeline.py --yesterday >> audit_training/logs/cron.log 2>&1
```

## Outputs

For each date, the pipeline writes:

```text
canonical/<date>.jsonl
sft/<date>.jsonl
tool_use_sft/<date>.jsonl
router_classification/<date>.jsonl
label_queue/<date>.jsonl
reports/<date>.rejects.jsonl
reports/<date>.stats.json
manifests/<date>.manifest.json
```

Files are written through `.tmp/` and then atomically moved into place.

## Optional Labeler

Set these environment variables to enable route-label model calls:

```text
AUDIT_LABEL_BASE_URL
AUDIT_LABEL_API_KEY
AUDIT_LABEL_MODEL
AUDIT_LABEL_TIMEOUT
```

Labeling currently runs sequentially in the streaming pipeline. If the labeler is disabled, unreachable, or returns an invalid response, the sample still exports with rule-based routing and no raw prompt or exception detail is written to outputs.

## Synthetic Samples

Safe synthetic generation uses `scripts/synthesize_training_samples.py` and does not read `/isos_data_share/audit` or send real audit-derived content to DeepSeek.

Create a local `.env` from `.env.example`:

```text
DEEPSEEK_API_KEY=your-key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
DEEPSEEK_TIMEOUT=30
```

Run:

```bash
scripts/run_synthetic_samples.sh --target-count 20 --batch-size 5
```

Outputs are written under:

```text
audit_training/synthetic_samples/samples.jsonl
audit_training/synthetic_samples/state.json
```

The writer appends one JSONL record at a time and updates `state.json` after each accepted sample. You can stop it with `Ctrl+C` and run the same command again to resume from existing `sample_id` values. Generated synthetic outputs and `.env` are ignored by Git.
