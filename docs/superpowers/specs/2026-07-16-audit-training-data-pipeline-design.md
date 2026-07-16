# Audit Training Data Pipeline Design

Date: 2026-07-16

## Context

The raw audit data lives under `/isos_data_share/audit/YYYY-MM-DD/`. Each date partition contains `_request_index.jsonl`, whose records point to per-request JSON files. The request details follow an OpenAI-compatible chat-completions shape with fields such as `request_body.messages`, `request_body.tools`, `response_body.choices`, `response_body.usage`, `model`, `status`, `session_id`, `user_id`, and related metadata.

The current workspace already has a `data/` directory containing several training formats, including `input/output`, `input/target`, and `instruction/input/output`. The new pipeline should put processed audit-derived training data under the current project's `data/` path without changing existing datasets.

## Goal

Build a scheduled, reproducible data-cleaning pipeline that converts daily audit logs into training-ready data for multiple tasks:

- Ordinary supervised fine-tuning.
- Tool-use or agent-style fine-tuning.
- Router classification training.
- Optional model-assisted labeling for uncertain routing samples.

The pipeline must prioritize stable intermediate data, privacy-preserving cleaning, auditability, and safe daily reruns.

## Chosen Approach

Use a canonical-first layered pipeline.

The first stage reads raw audit files and writes a normalized canonical JSONL file. Later stages derive task-specific datasets from that canonical layer. This avoids duplicated cleaning logic, keeps all task exports consistent, and allows future reruns when routing labels, filters, or training formats change.

The first version will not introduce a database. It will use manifest, statistics, reject, and label queue files to provide lightweight state and observability. A future version can replace or augment these files with SQLite if scale or retry needs grow.

## Output Layout

All generated data will be placed under:

```text
data/audit_training/
  canonical/YYYY-MM-DD.jsonl
  sft/YYYY-MM-DD.jsonl
  tool_use_sft/YYYY-MM-DD.jsonl
  router_classification/YYYY-MM-DD.jsonl
  label_queue/YYYY-MM-DD.jsonl
  reports/YYYY-MM-DD.stats.json
  reports/YYYY-MM-DD.rejects.jsonl
  manifests/YYYY-MM-DD.manifest.json
  logs/pipeline.log
```

Temporary writes should use:

```text
data/audit_training/.tmp/YYYY-MM-DD/
```

The final files should be replaced atomically after validation succeeds.

## Canonical Schema

Each line of `canonical/YYYY-MM-DD.jsonl` represents one cleaned request-response sample.

```json
{
  "sample_id": "sha256(date + request_id + normalized_messages)",
  "source": {
    "date": "2026-07-15",
    "request_id": "...",
    "file_path": "...",
    "tenant_hash": "...",
    "user_hash": "...",
    "session_hash": "..."
  },
  "request": {
    "model": "glm-5.2",
    "request_path": "/api/v1/openai/v1/chat/completions",
    "messages": [],
    "tools": [],
    "tool_choice": "auto",
    "params": {}
  },
  "response": {
    "message": {},
    "finish_reason": "stop",
    "usage": {}
  },
  "routing": {
    "weak_model_label": "glm-5.2",
    "weak_expert_label": null,
    "rule_label": null,
    "model_label": null,
    "label_confidence": "weak"
  },
  "quality": {
    "status": "accepted",
    "task_types": ["sft", "router"],
    "reject_reasons": [],
    "pii_redacted": true,
    "content_hash": "..."
  }
}
```

The canonical stage must:

- Stream `_request_index.jsonl`; never load a full day into memory.
- Load pointed request JSON files one at a time.
- Skip empty or malformed index lines without failing the whole run.
- Accept only records with successful status, valid messages, and valid response choices for training exports.
- Hash or omit direct identifiers such as user, tenant, session, API key, and client IP.
- Redact sensitive text inside messages and tool arguments.
- Record quality reasons for rejected or partially usable samples.
- Generate deterministic `sample_id` and `content_hash` values for reruns and deduplication.

## Task Exports

### Ordinary SFT

`sft/YYYY-MM-DD.jsonl` should contain records compatible with existing training styles while preserving chat structure.

```json
{
  "sample_id": "...",
  "instruction": "",
  "input": "redacted final user request or context",
  "output": "redacted assistant answer",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."},
    {"role": "assistant", "content": "..."}
  ],
  "metadata": {
    "source_date": "2026-07-15",
    "model": "glm-5.2"
  }
}
```

Eligibility:

- Successful response.
- No assistant tool call in the exported response.
- Non-empty assistant text.
- No high-risk filter failure.
- `finish_reason=length` is excluded by default.

### Tool-Use SFT

`tool_use_sft/YYYY-MM-DD.jsonl` should preserve the OpenAI-compatible structure rather than flattening tool calls.

```json
{
  "sample_id": "...",
  "messages": [],
  "tools": [],
  "response_message": {
    "role": "assistant",
    "tool_calls": []
  },
  "metadata": {
    "finish_reason": "tool_calls",
    "model": "..."
  }
}
```

Eligibility:

- Request contains usable `tools`, or assistant response contains usable `tool_calls`.
- Tool schemas and tool call arguments are parseable after redaction.
- Incomplete tool chains stay in canonical but are excluded from this export.

### Router Classification

`router_classification/YYYY-MM-DD.jsonl` should provide redacted inputs, lightweight features, and labels.

```json
{
  "sample_id": "...",
  "input": "redacted final user request or short context",
  "features": {
    "message_count": 4,
    "has_tools": true,
    "prompt_tokens": 1234,
    "client_type": "opencode"
  },
  "labels": {
    "weak_model_label": "glm-5.2",
    "rule_label": "tool_agent",
    "model_label": null,
    "final_label": "tool_agent",
    "confidence": "medium"
  }
}
```

The online `model` field is a weak label because it is currently selected manually. It should be retained as a signal, not treated as authoritative ground truth.

Initial route label set:

- `general_chat`
- `code_generation`
- `tool_agent`
- `long_context`
- `reasoning`
- `domain_qa`
- `unsafe_or_invalid`
- `unknown`

Final label priority:

1. High-confidence model-assisted label.
2. Rule label.
3. Mapped weak model label.
4. `unknown` and entry in `label_queue` when confidence is insufficient.

## Sensitive Data Handling

Default output must be redacted. Raw user text and assistant text must not be copied unchanged when sensitive values are detected.

Redaction should cover:

- Phone numbers.
- Email addresses.
- Chinese identity card numbers.
- Bank card-like numbers.
- IP addresses.
- API keys, Bearer tokens, AK/SK-like secrets, and long random secrets.
- URL query parameters that look like tokens, keys, or secrets.

Replacement should use stable placeholders inside each sample, such as `<PHONE_1>` and `<EMAIL_1>`. If the same sensitive value appears multiple times within one sample, it should receive the same placeholder so semantic relationships are preserved.

Metadata identifiers such as `user_id`, `tenant_id`, `session_id`, `api_key_id`, and `client_ip` must be hashed or omitted.

If redaction fails, the sample must not be exported to training data and must be recorded in rejects.

## Quality Rules

Hard rejects exclude samples from training exports and record them in `reports/YYYY-MM-DD.rejects.jsonl` without raw message content:

- Detail JSON parse failure.
- `status != success`.
- Missing `request_body.messages`.
- Missing `response_body.choices`.
- Empty assistant response.
- Response that appears to be only an error or exception.
- Prompt or response exceeds configured maximum character limits.
- Redaction failure.

Soft flags keep the sample in canonical but may exclude it from specific exports:

- `finish_reason=length`.
- Context too long for SFT export.
- Incomplete tool call chain.
- Conflicting route labels.
- Low confidence route label.

## Model-Assisted Labeling

Model-assisted route labeling is optional and must not block the daily cleaning job.

Configuration is provided by environment variables:

```text
AUDIT_LABEL_BASE_URL
AUDIT_LABEL_API_KEY
AUDIT_LABEL_MODEL
AUDIT_LABEL_TIMEOUT
```

The interface is OpenAI-compatible. When configured, the script may label low-confidence router samples or a configured sample subset.

Expected labeling response:

```json
{
  "label": "tool_agent",
  "confidence": 0.82,
  "reason": "Requires tool use and multi-step planning"
}
```

Timeouts, request failures, and invalid JSON responses must leave the sample in `label_queue/YYYY-MM-DD.jsonl` with a reason. Canonical, SFT, and tool-use exports must still be written.

## Scheduling

Default scheduled behavior is to process yesterday's partition.

Supported commands:

```bash
python scripts/audit_training_pipeline.py --date 2026-07-15
python scripts/audit_training_pipeline.py --start-date 2026-07-01 --end-date 2026-07-15
python scripts/audit_training_pipeline.py --yesterday
```

Example cron entry:

```bash
0 3 * * * cd /ai_paas_jf/sunlg && python scripts/audit_training_pipeline.py --yesterday >> data/audit_training/logs/pipeline.log 2>&1
```

The script should also support:

- `--dry-run`: process and report without replacing final output files.
- `--limit N`: process only the first N usable index records for validation.

## Idempotency and Observability

Idempotency:

- Write to a temporary date directory first.
- Validate schema and counts before replacing final files.
- Use deterministic sample and content hashes.
- Avoid appending duplicate records on rerun.

Manifest fields:

- Source date.
- Input partition path.
- Index line count.
- Files attempted.
- Files loaded.
- Output counts by task.
- Reject count by reason.
- Script version or content hash.
- Relevant configuration summary.
- Start and end timestamps.

Stats fields:

- Accepted and rejected counts.
- Export counts by task.
- Model distribution.
- Finish reason distribution.
- Tool-use count.
- Redaction hit counts.
- Label confidence distribution.

Logs must contain paths, counts, and error summaries only. They must not contain raw user message content.

## Implementation Shape

Initial implementation should avoid non-standard dependencies so it can run in the current environment.

Suggested files:

```text
scripts/audit_training_pipeline.py
data/audit_training/README.md
```

Suggested internal responsibilities:

- `iter_index_records()`: stream `_request_index.jsonl`.
- `load_audit_record()`: load per-request JSON with clear error reasons.
- `redact_text()` and `redact_message_tree()`: redact text and nested JSON structures.
- `build_canonical_sample()`: transform raw log records to canonical samples.
- `classify_by_rules()`: assign route labels from deterministic features.
- `export_sft()`: create ordinary SFT records.
- `export_tool_use_sft()`: create tool-use records.
- `export_router()`: create router classification records.
- `call_label_model()`: optionally call the OpenAI-compatible labeler.
- `write_outputs_atomically()`: write temp outputs and replace final files.
- `main()`: parse CLI, resolve date ranges, load configuration, and produce reports.

## Verification Plan

Unit-level fixtures should cover:

- Successful ordinary chat completion.
- Tool-call response.
- Failed request.
- Missing messages.
- Missing choices.
- Sensitive data redaction.
- Overlong prompt or response.
- Route label conflict.

Real-data smoke checks:

- `--dry-run --limit 100` on a recent audit partition.
- `--date YYYY-MM-DD --limit 1000` into temporary output.
- Validate JSONL parseability for every generated file.
- Confirm no raw direct identifiers appear in generated outputs.
- Confirm `stats.json`, `rejects.jsonl`, and `manifest.json` are written and internally consistent.

## Non-Goals

- Do not train or fine-tune a model in this pipeline.
- Do not modify existing datasets under `data/`.
- Do not require a database in the first version.
- Do not treat manually selected online `model` values as absolute router ground truth.
- Do not print raw user or assistant message content in logs or reject files.
