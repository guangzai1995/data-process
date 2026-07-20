# Audit Dedupe and Debug-Noise Suppression Design

Date: 2026-07-20

## Context

The audit training pipeline now has a canonical cleaning layer, quality metadata,
episode grouping, selected training exports, and optional safe model-assisted
labels. The current selected export path already prevents exact selected-record
duplicates through `selected_duplicate_key`, and it rejects obvious low-value
messages such as empty prompts and greetings.

That protection is useful, but it is still too narrow for real audit traffic.
Daily model-call logs often contain repeated debugging attempts, nearly identical
prompts, one-character confirmations, repeated "continue" turns, and prompt
variants that differ only by paths, numbers, IDs, or punctuation. Those records
should remain available for audit and diagnostics, but they should not dominate
training-facing datasets.

This design adds a dedicated dedupe and debug-noise layer before selected export.
It is a precision-first filter: when a record looks repetitive or noisy, the
pipeline marks it in quality metadata and excludes it from `selected/*` unless a
future config explicitly relaxes that behavior.

## Goals

- Suppress repeated and near-repeated samples from `selected/*` outputs.
- Preserve raw, canonical, legacy, and quality diagnostic outputs for traceability.
- Detect exact duplicates, normalized duplicates, near duplicates, and session
  debug bursts with deterministic local logic.
- Keep memory bounded for large daily partitions and spool mode.
- Report dedupe and noise rates without exposing raw prompts or linkable user data.
- Keep real audit data out of external model calls.

## Non-Goals

- Do not delete raw audit records, canonical records, legacy SFT exports, or
  diagnostic quality rows.
- Do not introduce a database in the first implementation.
- Do not use embeddings or external models for real audit dedupe in this phase.
- Do not attempt global cross-month semantic clustering.
- Do not make every repeated turn invalid for all purposes; router data may still
  retain some short but clear command forms when below configured caps.

## Options Considered

### Option A: Selected-Only Exact Dedupe

Keep the current `selected_duplicate_key` logic and add more tests around it.

This is simple and low risk, but it only catches exact or near-exact selected
export keys. It misses most debug noise because small prompt changes create new
keys.

### Option B: Quality-Layer Dedupe State

Add a local dedupe state that runs after quality annotation and before selected
export. It emits `risk_labels`, `reject_reasons`, and aggregate stats while
leaving canonical data untouched.

This is the recommended approach. It matches the existing pipeline shape,
supports both in-memory and spool modes, and keeps training-facing filtering
explainable.

### Option C: Offline Semantic Dedupe Job

Create a separate offline job that clusters historical outputs with embeddings or
LLM judgments.

This may become useful later, but it needs a stronger privacy design and more
operational complexity. It is out of scope for the first implementation.

## Chosen Approach

Implement Option B as a deterministic, bounded-memory dedupe layer:

```text
raw audit
  -> canonical cleaning and redaction
  -> route and quality annotation
  -> dedupe and debug-noise annotation
  -> refresh selected eligibility
  -> quality reports
  -> selected exports
```

The layer has two responsibilities:

- Annotate records with dedupe/noise signals.
- Prevent flagged records from entering `selected/*` by adding hard
  `reject_reasons` where appropriate.

The existing selected-export `seen` sets remain as the final guardrail.

## Classification Labels

Add the following reject reasons:

- `duplicate_content`: identical selected-training signature already observed.
- `normalized_duplicate_content`: normalized prompt/response signature already
  observed in the relevant route and intent bucket.
- `near_duplicate_content`: SimHash or token-overlap similarity exceeds the
  configured threshold in the same task bucket.
- `debug_noise_repeat`: repeated low-information debug/control turn in a
  user-session window.
- `debug_burst`: one user-session emits too many samples for the same task
  fingerprint in a short window.

Add the following risk labels:

- `duplicate`
- `near_duplicate`
- `debug_noise`
- `debug_burst`
- `dedupe_state_saturated`

`duplicate`, `near_duplicate`, and `debug_noise` are hard selected-export
filters by default. `dedupe_state_saturated` is diagnostic only; it means the
bounded state dropped old representatives and near-duplicate recall may be lower.

## Normalization

Add a reusable normalization function for dedupe signatures. It should be
stricter than display normalization but still irreversible after hashing.

Rules:

- Convert ASCII letters to lowercase.
- Trim leading and trailing whitespace.
- Collapse repeated whitespace.
- Normalize common CJK and ASCII punctuation to spaces where it only separates
  terms.
- Replace numbers with `<num>`.
- Replace redaction placeholders such as `<SECRET_1>` with `<redacted>`.
- Replace path-like fragments and URLs that survived redaction with generic
  placeholders.
- Collapse repeated control words such as "continue continue" to one token.
- Cap normalized text before hashing.

The pipeline should store only hashes and compact numeric fingerprints in state
and reports. It should not emit normalized raw text.

## Signatures

For each canonical record, compute a `dedupe` block inside `quality`:

```json
{
  "dedupe": {
    "prompt_hash": "sha256-prefix",
    "response_hash": "sha256-prefix",
    "prompt_response_hash": "sha256-prefix",
    "task_signature_hash": "sha256-prefix",
    "simhash64": "hex64",
    "bucket": "route:intent:score_bucket",
    "decision": "selected_candidate",
    "matched_reason": null
  }
}
```

The exported quality row may include this block because it contains only hashes
and coarse labels. Selected training records should not include these internal
hashes unless a future design explicitly needs them.

Signature inputs:

- Router duplicate key: normalized prompt + route + intent.
- SFT duplicate key: normalized prompt + normalized assistant response + route
  + intent.
- Tool-use duplicate key: normalized prompt + sorted tool names + route + intent.
- Task signature: task fingerprint + route + intent + sorted tool names.

## Exact And Normalized Dedupe

Maintain hash sets per output kind:

```text
seen.router
seen.sft
seen.tool_use_sft
seen.prompt_by_bucket
seen.task_signature_by_day
```

When a record is already in a relevant set:

- Add `duplicate_content` for exact selected export signature matches.
- Add `normalized_duplicate_content` for normalized prompt or
  prompt-response matches.
- Add `duplicate` to `risk_labels`.
- Remove all `use_for` entries that would export the duplicate.

If a record has high value labels but is duplicated, do not export it by default.
The first selected copy should win because records are processed by quality rank
before selected export in memory mode, and by source order in spool mode. A later
implementation can add a replacement strategy for spool mode if needed.

## Near-Duplicate Detection

Use SimHash as the first near-duplicate mechanism because it is deterministic,
compact, and does not require external dependencies.

Algorithm:

1. Tokenize normalized prompt into character n-grams and word tokens.
2. Compute a 64-bit SimHash.
3. Look up representatives in the same route/intent/task bucket.
4. Treat records as near duplicates when Hamming distance is at or below the
   configured threshold.
5. Optionally confirm with token Jaccard overlap to reduce false positives for
   very short text.

Default thresholds:

```text
near_duplicate_simhash_hamming = 4
near_duplicate_min_chars = 16
near_duplicate_min_tokens = 4
near_duplicate_jaccard = 0.88
max_near_duplicate_representatives_per_bucket = 128
```

Short text below the minimum size should be handled by low-information and debug
noise rules instead of SimHash.

## Debug-Noise Detection

Add session-window rules for low-value repeated workflow control messages.

Control/noise terms include:

```text
continue, retry, again, test, ok, yes, no, a, b, 1, 2, 继续, 重试, 再来, 测试, 不对,
好的, 可以, 嗯, 是, 否
```

Rules:

- `debug_noise_repeat`: same user-session emits the same normalized control turn
  more than `max_debug_control_repeats_per_session` times in one date partition.
- `debug_burst`: same user-session and task fingerprint exceeds
  `max_debug_task_burst_per_session` within `debug_burst_window_minutes`.
- `continuation_without_context`: continuation terms can be a risk label when
  the episode builder cannot link them to prior useful context; in this first
  implementation, map this to `debug_noise_repeat` only when repeated.

Default thresholds:

```text
max_debug_control_repeats_per_session = 2
max_debug_task_burst_per_session = 8
debug_burst_window_minutes = 20
```

Short but clear router prompts can remain eligible while they are below the
repeat threshold. Once `debug_noise_repeat` or `debug_burst` is emitted, all
selected eligibility should be removed for that record by default.

## Memory Model

The dedupe state must be bounded.

Use per-date state:

```text
DedupeState
  seen hashes per selected kind
  prompt hashes per bucket
  SimHash representatives per bucket
  user-session rolling counters
  aggregate report counters
```

Bounded collections:

- Each bucket keeps at most `max_near_duplicate_representatives_per_bucket`
  representatives.
- User-session counters keep at most
  `max_dedupe_user_session_windows` active windows.
- Hash sets can switch to capped LRU sets after `max_dedupe_seen_hashes`.
- When a cap is reached, increment `dedupe_state_saturated` in report counters.

Default caps:

```text
max_dedupe_seen_hashes = 1000000
max_dedupe_user_session_windows = 100000
max_near_duplicate_buckets = 50000
```

These defaults are intentionally high enough for daily partitions but safe for
spool mode. They should be configurable through CLI flags and `process_date`
keyword arguments.

## Spool Mode

Spool mode must not load all annotated records into memory. The dedupe layer
should run inside `process_spooled_selection_records` before
`consider_selected_record` writes selected outputs.

Spool behavior:

- Read one canonical record from spool.
- Update report state.
- Apply dedupe/noise annotation using bounded `DedupeState`.
- Refresh selected eligibility if reject reasons changed.
- Write quality diagnostics.
- Consider selected export.

This preserves the current memory-safety contract while improving selected
filtering.

## Reporting

Extend `quality_stats` with:

```json
{
  "risk_labels": {},
  "dedupe": {
    "duplicate_content": 0,
    "normalized_duplicate_content": 0,
    "near_duplicate_content": 0,
    "debug_noise_repeat": 0,
    "debug_burst": 0,
    "state_saturated": 0
  }
}
```

Extend `selection_manifest.selection` with:

```json
{
  "dedupe_enabled": true,
  "dedupe_rejected": 0,
  "dedupe_config": {
    "near_duplicate_simhash_hamming": 4,
    "max_debug_control_repeats_per_session": 2
  }
}
```

All counts should remain k-suppressed where they could reveal rare behavior.
Reports must not include raw prompts, raw responses, raw identifiers, file paths,
or direct request IDs.

## Configuration

Add default config keys:

```text
enable_dedupe = true
enable_near_duplicate_dedupe = true
enable_debug_noise_filter = true
near_duplicate_simhash_hamming = 4
near_duplicate_min_chars = 16
near_duplicate_min_tokens = 4
near_duplicate_jaccard = 0.88
max_near_duplicate_representatives_per_bucket = 128
max_debug_control_repeats_per_session = 2
max_debug_task_burst_per_session = 8
debug_burst_window_minutes = 20
max_dedupe_seen_hashes = 1000000
max_dedupe_user_session_windows = 100000
max_near_duplicate_buckets = 50000
```

CLI flags should mirror these keys. `--disable-dedupe` should disable all new
dedupe/noise filtering while leaving the existing selected-export exact `seen`
guard in place.

## Interaction With Existing Logic

- Existing greeting and too-short hard rejects run first.
- Model-assisted quality labels cannot rescue deterministic dedupe rejects.
- Existing selected-export exact duplicate checks remain as a final safety net.
- Quota checks run after dedupe. A duplicate should be counted as duplicate, not
  quota exceeded.
- Episode builder should exclude episodes where every turn is dedupe/noise
  rejected.
- `multi_turn_sft` should not export episodes containing rejected turns unless a
  future design adds turn-pruning.

## Testing Strategy

Unit tests:

- Exact selected duplicate is flagged and excluded.
- Normalized duplicate with different whitespace, punctuation, or numbers is
  flagged and excluded.
- Near duplicate above threshold is flagged in the same bucket.
- Similar text in different route/intent buckets is not falsely rejected.
- Very short actionable router prompts are not handled by SimHash.
- Repeated control turns in one user-session trigger `debug_noise_repeat`.
- Task burst threshold triggers `debug_burst`.
- Dedupe rejects cannot be rescued by model-assisted high quality scores.
- Report state includes risk label counts and dedupe summary counts.
- State caps add `dedupe_state_saturated` without crashing.

Integration tests:

- In-memory selection and spool selection produce compatible selected counts for
  a fixture with duplicates and debug bursts.
- Quality output contains safe dedupe metadata but no raw prompt text.
- Selected outputs exclude dedupe/noise rejects.
- Legacy outputs remain unchanged for backward compatibility.
- CLI disable flags preserve old behavior except for the final selected `seen`
  safety net.

## Acceptance Criteria

- Repeated debug/control messages are absent from `selected/*` by default.
- Exact, normalized, and near duplicates are explainable through quality metadata
  and reports.
- Raw, canonical, legacy, and diagnostic outputs remain available.
- Memory use stays bounded in both in-memory and spool modes.
- No external model call is required for real audit dedupe.
- Reports expose duplicate/noise rates without raw prompts or linkable IDs.
- Existing tests continue to pass, and new tests cover the dedupe/noise rules.
