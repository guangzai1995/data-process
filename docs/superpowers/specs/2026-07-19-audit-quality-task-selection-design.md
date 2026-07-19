# Audit Quality, Task, and User-Aware Selection Design

Date: 2026-07-19

## Context

The current audit pipeline converts each successful audit request into one canonical training sample. Each sample keeps hashed `tenant_hash`, `user_hash`, and `session_hash` metadata and can be exported to ordinary SFT, tool-use SFT, and router-classification files.

That canonical-first design is still the right foundation, but the current export path is too permissive for training data selection. It does not yet use user-level distribution controls, task-level grouping, near-duplicate suppression, or a training-value score. As a result, low-value messages such as greetings, probes, repeated short requests, incomplete tasks, or overrepresented high-frequency users can enter training exports.

This design adds a quality and selection layer above the existing canonical layer. The goal is a high-precision training set: it is acceptable to filter aggressively at first, as long as rejects are auditable and the canonical data remains available for future reprocessing.

## Goals

- Preserve the existing canonical single-request layer as the immutable cleaned source.
- Add explicit quality scoring and usage eligibility for each canonical sample.
- Add user-aware and task-aware selection so high-frequency users and repeated tasks do not dominate training data.
- Add an episode layer for multi-turn user tasks, without requiring a database in the first implementation.
- Produce selected training exports that are safer defaults than the current raw task exports.
- Keep all raw audit data and local secrets out of Git and out of external model calls.

## Non-Goals

- Do not remove the current canonical, SFT, tool-use SFT, or router exports in the first pass.
- Do not send raw audit records, raw identifiers, unredacted prompts, raw file paths, API keys, IP addresses, or session identifiers to any external model.
- Do not make model-assisted labels authoritative. Model labels are advisory and must be constrained by hard safety filters and deterministic rules.
- Do not introduce a database in the first implementation. JSONL outputs and JSON reports are enough for the current pipeline scale and auditability needs.

## Chosen Approach

Use a layered selection pipeline:

```text
raw audit
  -> canonical single-request cleaning
  -> quality scoring and eligibility
  -> user/task grouping and episode building
  -> selection, deduplication, and quota controls
  -> selected task exports
```

The pipeline will keep two kinds of exports:

- Existing raw task exports: direct derivatives of accepted canonical samples, useful for debugging and backward compatibility.
- New selected task exports: filtered and balanced datasets intended as the default training input.

The selected exports should become the recommended training entrypoint once implementation is complete.

## Data Grain

### Sample Grain

A sample is one cleaned request-response pair from the current canonical pipeline. It is the source grain for router classification and simple single-turn SFT.

Sample-level fields are used to determine structural validity, redaction safety, route label, basic content quality, duplicate content, and direct training eligibility.

### Episode Grain

An episode is a short sequence of samples that represent one user working on one task. It is the source grain for multi-turn SFT and complete tool-use traces.

Episode grouping uses only redacted and hashed metadata:

```text
tenant_hash + user_hash + session_hash + route_label + task_fingerprint + time_window
```

The first implementation should use `session_hash` when present. If `session_hash` is missing, it should group by `tenant_hash + user_hash + time_window`, with a conservative maximum gap between adjacent samples. A 30-minute gap is the default maximum until data profiling suggests a better threshold.

### User-Day Grain

A user-day is not a training example. It is a distribution-control unit used for quotas and diagnostics.

User-day stats should track accepted, rejected, selected, route labels, task fingerprints, duplicate rates, and high-value counts for each `date + tenant_hash + user_hash`.

## Task Identity

Each sample should receive a task block:

```json
{
  "task": {
    "route_label": "code_generation",
    "intent_label": "debug_python_error",
    "task_fingerprint": "sha256-prefix",
    "episode_id": "sha256-prefix",
    "turn_index": 0
  }
}
```

### Route Label

`route_label` should be the selected router label from existing rule and optional model-label logic. If rule and model label disagree with low confidence, use `unknown` or queue the record for review rather than forcing a precise label.

### Intent Label

`intent_label` is a coarse task intent. The first implementation can derive it from deterministic rules and route-specific keywords. Model-assisted intent labels can be added later after redaction, truncation, and hard filters.

Initial intent examples:

- `greeting_or_probe`
- `general_question`
- `code_generation`
- `code_debugging`
- `sql_generation`
- `shell_or_script`
- `tool_lookup`
- `document_summary`
- `long_context_analysis`
- `domain_qa`
- `unsafe_or_invalid`
- `unknown`

### Task Fingerprint

`task_fingerprint` should be deterministic and should not contain raw text. It should hash a normalized, redacted task signature:

```text
route_label + intent_label + normalized_last_user_text + tool_names + coarse_time_bucket
```

Normalization should lowercase ASCII, trim whitespace, collapse repeated whitespace, remove redaction counters where possible, and cap text length before hashing. This fingerprint is for grouping and deduplication, not for reconstructing text.

## Quality Model

Every canonical sample should receive a quality block. The block should be stable, inspectable, and rule-first.

```json
{
  "quality": {
    "status": "accepted",
    "task_types": ["router", "sft"],
    "quality_score": 0.86,
    "value_labels": ["high_value_code", "clear_intent"],
    "risk_labels": [],
    "reject_reasons": [],
    "use_for": ["router", "sft"],
    "pii_redacted": false,
    "redaction_stats": {},
    "content_hash": "sha256"
  }
}
```

The existing `quality` fields should be extended rather than replaced.

### Hard Rejects

A hard reject removes a sample from selected training exports. It can still remain in canonical rejects or quality reports.

Hard reject reasons:

- `greeting_only`: user text is only greeting, thanks, acknowledgement, or probe.
- `too_short_no_intent`: final user text is too short and no clear actionable intent is detected.
- `empty_user_text`: no usable user text after extraction.
- `empty_after_redaction`: redaction leaves only placeholders or punctuation.
- `assistant_low_information`: assistant response is empty, generic, or only acknowledgement without useful content.
- `duplicate_content`: exact `content_hash` already selected for the same date or prior loaded selection state.
- `near_duplicate_content`: normalized user text and route are near-duplicate within the same task bucket.
- `incomplete_length_response`: response ended with `finish_reason=length` and no continuation is linked.
- `invalid_tool_trace`: tool schema, tool call, or arguments are invalid for tool-use SFT.
- `redaction_risk`: content still appears to contain sensitive data after redaction.
- `unsafe_or_invalid`: the content is unsafe or unusable for training.

### Soft Risk Labels

Soft risk labels do not automatically remove the sample, but they lower the score or restrict `use_for`.

Soft labels:

- `short_but_clear`
- `single_turn_generic`
- `label_conflict`
- `low_confidence_route`
- `high_redaction_density`
- `possible_template_answer`
- `high_frequency_user`
- `quota_limited`

### Value Labels

Value labels raise score or protect samples from aggressive downsampling.

Value labels:

- `clear_intent`
- `high_value_code`
- `high_value_debugging`
- `high_value_sql`
- `high_value_tool_use`
- `high_value_reasoning`
- `high_value_long_context`
- `high_value_domain_task`
- `multi_turn_task`
- `complete_tool_trace`
- `structured_answer`

## Scoring Rules

Use deterministic scoring first. A simple additive score is preferred for auditability.

Initial score bands:

```text
0.00-0.29: reject from selected exports
0.30-0.49: router only if route signal is useful
0.50-0.69: usable but lower priority
0.70-0.84: good selected sample
0.85-1.00: high-value selected sample
```

Base score starts at `0.50` after the existing canonical structural checks pass.

Positive adjustments:

- `+0.20` clear actionable user intent.
- `+0.15` code, SQL, debugging, reasoning, domain, or long-context task.
- `+0.15` complete tool trace.
- `+0.10` multi-turn episode with coherent progression.
- `+0.10` structured assistant answer.
- `+0.05` non-empty useful system/developer context after redaction.

Negative adjustments:

- `-0.30` very short content with only weak intent.
- `-0.25` generic assistant response.
- `-0.20` high redaction density.
- `-0.20` label conflict or low route confidence.
- `-0.15` near duplicate.
- `-0.10` overrepresented user/day bucket.

Hard rejects override score and set `use_for` to an empty list.

## Greeting and Low-Value Filter

The first implementation should include a conservative greeting/probe detector.

Examples that should be hard-rejected when they appear as the only user intent:

```text
hello
hi
hey
你好
您好
在吗
谢谢
ok
好的
测试
test
ping
1
.
```

The detector should normalize whitespace, punctuation, common full-width punctuation, and simple case differences. It should avoid rejecting short but actionable requests such as:

```text
写 SQL
改 bug
解释下
生成脚本
查天气
```

Short actionable requests can be retained with `short_but_clear` and restricted to router unless the assistant response is clearly useful.

## Deduplication

Use layered deduplication:

- Exact duplicate: existing `content_hash` match.
- User text duplicate: hash of normalized final user text.
- Task duplicate: same `task_fingerprint` and very similar route/intent in one date partition.
- Episode duplicate: same ordered sequence of task fingerprints and response hashes.

The first implementation should handle exact duplicate and normalized user-text duplicate. Near-duplicate detection can start with normalized text equality and simple containment rules. Embedding-based deduplication is out of scope for the first pass.

## User and Task Quotas

Selection should avoid letting high-frequency users dominate.

Default quotas:

```text
max_selected_sft_per_user_per_day = 20
max_selected_router_per_user_per_day = 100
max_selected_tool_use_per_user_per_day = 50
max_selected_per_task_fingerprint_per_day = 20
```

High-value samples can bypass task-fingerprint quotas up to a separate cap:

```text
max_high_value_per_task_fingerprint_per_day = 50
```

Quota decisions should be recorded with `quota_limited` and should not delete canonical samples. The selection layer decides whether a sample enters `selected/*` outputs.

## Episode Builder

The episode builder reads quality-annotated canonical records for a date and outputs `episodes/YYYY-MM-DD.jsonl`.

Episode schema:

```json
{
  "episode_id": "sha256-prefix",
  "source": {
    "date": "2026-07-19",
    "tenant_hash": "tenant_hash_0123456789abcdef",
    "user_hash": "user_hash_0123456789abcdef",
    "session_hash": "session_hash_0123456789abcdef"
  },
  "task": {
    "route_label": "code_generation",
    "intent_label": "code_debugging",
    "task_fingerprint": "task_fp_0123456789abcdef"
  },
  "turns": [
    {
      "sample_id": "sample_0123456789abcdef",
      "turn_index": 0,
      "messages": [],
      "response_message": {},
      "tools": [],
      "quality_score": 0.82,
      "use_for": ["sft"]
    }
  ],
  "quality": {
    "episode_score": 0.84,
    "value_labels": ["multi_turn_task"],
    "risk_labels": [],
    "reject_reasons": [],
    "use_for": ["multi_turn_sft"]
  }
}
```

Episode selection rules:

- Minimum one useful turn.
- Prefer two or more coherent turns for multi-turn SFT.
- Exclude episodes where every turn is greeting, probe, duplicate, or low-information.
- Tool-use episodes require valid tool definitions and tool calls for every exported tool-use turn.
- Preserve turn order by source timestamp if available; otherwise preserve index order within the date partition.

If timestamps are unavailable or unreliable, the first implementation should only build episodes within a single date partition and a single session hash.

## Selected Exports

Add selected output directories:

```text
selected/sft/YYYY-MM-DD.jsonl
selected/tool_use_sft/YYYY-MM-DD.jsonl
selected/router_classification/YYYY-MM-DD.jsonl
selected/multi_turn_sft/YYYY-MM-DD.jsonl
```

Selected exports should use the existing export formats where possible, with richer metadata:

```json
{
  "metadata": {
    "source_date": "2026-07-19",
    "model": "glm-5.2",
    "quality_score": 0.86,
    "value_labels": ["high_value_code"],
    "intent_label": "code_debugging",
    "task_fingerprint": "task_fp_0123456789abcdef"
  }
}
```

The old `sft/`, `tool_use_sft/`, and `router_classification/` outputs remain available for comparison. Training jobs should prefer `selected/*` once validated.

## Model-Assisted Labeling

Model-assisted labeling is allowed only after deterministic safety gates:

1. Existing structural validation passes.
2. Text has been redacted.
3. Hard rejects for raw safety and obvious low-value samples have run.
4. Input sent to the model is truncated to the minimum useful context.
5. Payload excludes request IDs, file paths, tenant/user/session hashes, API keys, raw request bodies, raw response bodies, and raw audit metadata.

The model can propose:

- `route_label`
- `intent_label`
- `quality_score`
- `value_labels`
- `risk_labels`
- `reason`

The model cannot override:

- redaction risk
- invalid schema
- hard reject rules
- quota limits
- deterministic duplicate suppression

Low-confidence or malformed model responses should degrade safely to rule-only labels and write an audit-safe reason to `label_queue` or reports.

## Reports and Stats

Add reports:

```text
reports/YYYY-MM-DD.quality_stats.json
reports/YYYY-MM-DD.user_task_stats.json
reports/YYYY-MM-DD.selection_manifest.json
```

`quality_stats` should include:

- total canonical accepted
- hard rejected by reason
- soft risk label counts
- value label counts
- score histogram
- selected counts by export type
- route and intent distribution

`user_task_stats` should include:

- selected samples by user-day bucket
- quota-limited counts
- top task fingerprints by count
- duplicate and near-duplicate counts
- high-value samples by task type

`selection_manifest` should include:

- input canonical path
- output selected paths
- selection config values
- pipeline version
- started and finished timestamps
- counts for accepted, rejected, selected, and quota-limited samples

No report should include raw prompts, raw identifiers, raw file paths, or unredacted content.

## Output Layout

The complete target output layout becomes:

```text
audit_training/
  canonical/YYYY-MM-DD.jsonl
  quality/YYYY-MM-DD.jsonl
  episodes/YYYY-MM-DD.jsonl
  sft/YYYY-MM-DD.jsonl
  tool_use_sft/YYYY-MM-DD.jsonl
  router_classification/YYYY-MM-DD.jsonl
  selected/sft/YYYY-MM-DD.jsonl
  selected/tool_use_sft/YYYY-MM-DD.jsonl
  selected/router_classification/YYYY-MM-DD.jsonl
  selected/multi_turn_sft/YYYY-MM-DD.jsonl
  label_queue/YYYY-MM-DD.jsonl
  reports/YYYY-MM-DD.rejects.jsonl
  reports/YYYY-MM-DD.stats.json
  reports/YYYY-MM-DD.quality_stats.json
  reports/YYYY-MM-DD.user_task_stats.json
  reports/YYYY-MM-DD.selection_manifest.json
  manifests/YYYY-MM-DD.manifest.json
```

All generated outputs remain ignored by Git.

## Implementation Phases

### Phase 1: Quality and Selected Single-Turn Exports

- Extend canonical quality metadata with `quality_score`, `value_labels`, `risk_labels`, and `use_for`.
- Add deterministic greeting, too-short, low-information, duplicate, and redaction-density filters.
- Add user-day and task-fingerprint quota tracking in memory for one date partition.
- Add `quality/YYYY-MM-DD.jsonl` and `selected/*` exports.
- Add quality, user-task, and selection reports.

This phase makes selected training exports safer without changing the raw canonical layer.

### Phase 2: Episode Layer

- Build `episodes/YYYY-MM-DD.jsonl` from quality-annotated canonical records.
- Add episode scoring and multi-turn eligibility.
- Export selected multi-turn SFT records.
- Add complete tool-use episode selection where tool traces are valid.

### Phase 3: Safer Model-Assisted Intent and Quality Labels

- Add optional model-assisted labels for redacted, filtered, truncated samples.
- Keep rule-only fallback and label queue for uncertain samples.
- Compare model-assisted labels against deterministic labels in reports before relying on them for training selection.

## Testing Strategy

Unit tests should cover:

- Greeting-only and probe-only hard rejects.
- Short actionable requests are not rejected as greetings.
- Empty-after-redaction and high-redaction-density handling.
- Exact duplicate and normalized text duplicate suppression.
- User-day and task-fingerprint quota behavior.
- `quality_score` score bands and hard-reject override.
- `use_for` selection for router, SFT, tool-use SFT, and multi-turn SFT.
- Episode grouping by session, user, route, task fingerprint, and time gap.
- Selected exports exclude hard rejects and include expected metadata.
- Reports do not contain raw prompts or direct identifiers.
- Model-assisted label failures degrade to rule-only outputs.

Integration tests should run a small fixture date through the full pipeline and assert that:

- canonical output remains available;
- quality output has one record per canonical accepted record;
- selected outputs contain only eligible records;
- rejected and quota-limited samples are explainable through reports;
- generated JSON is strict and parseable with `allow_nan=False` expectations.

## Acceptance Criteria

The design is implemented when:

- Training users can choose `selected/*` as the default high-precision training input.
- Obvious greetings, probes, duplicates, and low-information samples are absent from selected training exports.
- High-frequency users are capped by configurable user-day quotas.
- Task fingerprints are available for grouping, deduplication, and stats.
- Episode output exists and can power multi-turn training exports after Phase 2.
- Every filtered sample has an auditable reason in quality output or reports.
- No raw audit identifiers or unredacted sensitive content are written to selected outputs or reports.
