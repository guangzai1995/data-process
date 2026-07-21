# Audit Training Outputs

This directory is the default output root for `scripts/audit_training_pipeline.py`.
Generated dataset files are ignored by Git by default. Keep only this README under version control.

## Runs

Daily run:

```bash
scripts/run_audit_training_pipeline.sh
```

The wrapper loads `.env`, defaults to `--yesterday`, and passes any explicit CLI flags through:

```bash
scripts/run_audit_training_pipeline.sh --date 2026-07-15 --dry-run --limit 100
```

Backfill:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_training_pipeline.py --start-date 2026-07-01 --end-date 2026-07-15
```

Validation run without final outputs:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_training_pipeline.py --date 2026-07-15 --limit 100 --dry-run
```

Progress logging for longer runs writes aggregate JSON lines to stderr and keeps stdout machine-readable:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_training_pipeline.py --date 2026-07-15 --limit 100 --progress-every 25
```

Legacy-only compatibility run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_training_pipeline.py --date 2026-07-15 --compat-output-set
```

Cron example:

```cron
15 2 * * * cd /path/to/repo && PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_training_pipeline.py --yesterday >> audit_training/logs/cron.log 2>&1
```

## Output Sets

Default runs write legacy raw exports plus selected training exports and restricted diagnostics:

```text
canonical/<date>.jsonl
sft/<date>.jsonl
tool_use_sft/<date>.jsonl
router_classification/<date>.jsonl
label_queue/<date>.jsonl
quality/<date>.jsonl
episodes/<date>.jsonl
selected/sft/<date>.jsonl
selected/tool_use_sft/<date>.jsonl
selected/router_classification/<date>.jsonl
selected/multi_turn_sft/<date>.jsonl
reports/<date>.rejects.jsonl
reports/<date>.stats.json
reports/<date>.quality_stats.json
reports/<date>.user_task_stats.json
reports/<date>.selection_manifest.json
manifests/<date>.manifest.json
```

`canonical/*`, `quality/*`, and `episodes/*` are restricted diagnostics. Use `selected/*` for training. Selected records omit `sample_id`, request IDs, tenant/user/session hashes, file path hashes, internal task fingerprints, and content hashes. Reports use aggregate buckets with k-threshold suppression.

Useful output switches:

```text
--disable-selection      Write legacy outputs only; disables quality, selected, episodes, and selection reports.
--disable-episodes       Keep single-turn selected outputs but skip episodes and selected multi-turn SFT.
--disable-diagnostics    Skip canonical, quality, and episodes files while still computing selected outputs.
--compat-output-set      Alias for legacy-only compatibility output. Conflicts with model labeler flags.
--disable-dedupe         Disable quality-layer dedupe and debug noise rejects; selected exports keep a final exact seen guard.
--disable-near-duplicate-dedupe
                         Disable near-duplicate rejects while keeping exact/normalized duplicate and debug noise filters.
--disable-debug-noise-filter
                         Disable repeated control-turn and debug burst rejects.
```

Selection controls include score thresholds, per-user/task quotas, `--selection-mode auto|in-memory|spool`, `--max-in-memory-samples`, and `--max-selection-memory-mb`. By default, selected training outputs filter exact duplicate, normalized duplicate, near duplicate, repeated debug/control turns, and debug burst records before export. `--disable-dedupe` disables quality-layer dedupe/debug noise reject reasons, but selected exports still keep a final exact seen guard so duplicate selected records are not written.

Dedupe and debug noise thresholds include `--near-duplicate-simhash-hamming`, `--near-duplicate-jaccard`, `--max-debug-control-repeats-per-session`, and `--max-debug-task-burst-per-session`. Auto mode switches to a run-specific spool under `.tmp/` before retaining more records than configured. Dry runs exercise the same decision path and clean temp/spool files afterward.

`reports/<date>.quality_stats.json` (`quality_stats`) includes aggregate `risk_labels` and `dedupe` counts. The selection manifest includes `dedupe_enabled`, `dedupe_rejected`, and `dedupe_config`.

Quality/report dedupe metadata is limited to hashes, coarse buckets, counts, and decisions. It does not include raw prompts/responses, request IDs, tenant/user/session hashes, file paths, `request_id`, `tenant_hash`, `user_hash`, `session_hash`, `file_path_hash`, `content_hash`, or `task_fingerprint_internal`. Selected outputs do not include internal dedupe hash fields.

## Optional Labelers

Set these environment variables for model-assisted route or quality labels:

```text
AUDIT_LABEL_BASE_URL
AUDIT_LABEL_API_KEY
AUDIT_LABEL_MODEL
AUDIT_LABEL_TIMEOUT
AUDIT_LABEL_CACHE
AUDIT_LABEL_CACHE_MAX_ENTRIES
AUDIT_SELECTION_HMAC_KEY
```

Environment variables alone do not trigger external calls. Add explicit flags:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_training_pipeline.py --date 2026-07-15 --enable-route-labeler
PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_training_pipeline.py --date 2026-07-15 --enable-quality-labeler
```

Labeler payloads are feature-only by default. Redacted snippets are sent only with `--enable-label-snippets`, and only after local leakage scanning passes. Positive model suggestions cannot override hard rejects, duplicate suppression, quotas, invalid tool traces, or deterministic threshold eligibility. Negative quality risk can downrank or remove selected eligibility.

Model-assisted labeling uses an in-process payload-hash cache by default so repeated feature-only payloads do not trigger duplicate HTTP requests. Set `AUDIT_LABEL_CACHE=0` to disable it or `AUDIT_LABEL_CACHE_MAX_ENTRIES` to bound entries. Quality model calls are skipped for samples that deterministic local quality already rejects or cannot make selected-eligible; reports expose aggregate `requests`, `cache_hits`, `cache_stores`, `cache_evictions`, `skips`, and `errors` counters under `labeler`.

## Safety

Real audit data lives outside this repo under `/isos_data_share/audit`. Do not commit raw data, generated outputs, `.env`, or provider keys. The pipeline writes through `.tmp/` and atomically commits the enabled output matrix. A per-date lock prevents concurrent selected runs for the same output root.

## Synthetic Samples

Safe synthetic generation uses `scripts/synthesize_training_samples.py` and does not read `/isos_data_share/audit` or send real audit-derived content to DeepSeek.

Create a local `.env` from `.env.example` and run. `DEEPSEEK_MAX_RETRIES` defaults to 10 so transient network or malformed-model-output batches can retry before the resumable runner stops:

```bash
scripts/run_synthetic_samples.sh --target-count 20 --batch-size 5
```

Outputs are written under:

```text
audit_training/synthetic_samples/samples.jsonl
audit_training/synthetic_samples/state.json
```

The writer appends one JSONL record at a time and updates `state.json` after each accepted sample. You can stop it with `Ctrl+C` and run the same command again to resume from existing `sample_id` values. Generated synthetic outputs and `.env` are ignored by Git.
