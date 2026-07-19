# Plan: Audit Quality, Task, Episode, and Model-Assisted Selection Pipeline
_Locked via grill — by Claude + user; revised after Codex review_

## Goal

Implement the full Phase 1 through Phase 3 upgrade for the audit training data pipeline so training exports are selected by user-aware, task-aware, quality-scored criteria rather than exporting every structurally valid request. The implementation must preserve the existing canonical-first pipeline and old raw task exports for compatibility, add high-precision `selected/*` exports for training, support conservative episode-level multi-turn grouping, and provide optional model-assisted route/quality labeling through the existing `AUDIT_LABEL_*` configuration. External model payloads are feature-only by default and must never include raw audit data, linkable identifiers, hashes, file paths, deterministic text fingerprints, or free-text snippets unless a future explicit snippet approval flag is set and the local leakage scan passes.

## Approach

1. Keep implementation in `scripts/audit_training_pipeline.py` for this pass, but define internal pure-function sections with clear interfaces:
   - `task_identity`: route/intent labels, normalized text, internal fingerprints, export-safe buckets.
   - `quality_scoring`: hard rejects, value/risk labels, deterministic score, model-adjusted report score.
   - `selection_state`: duplicate keys, quota ranking, user/task counters.
   - `selection_storage`: in-memory views, spool views, memory estimates, run locks.
   - `episode_builder`: event ordering, deterministic continuation predicates, episode scoring.
   - `safe_labeling`: leakage scan, safe route/quality payloads, response parsing, degradation.
   - `selected_exports`: privacy-safe selected SFT, tool-use SFT, router, multi-turn SFT.
   - `selection_reports`: quality, user/task, manifest, k-thresholded bucket reporting.

2. Classify output sensitivity and add schema versions:
   - `canonical/*`, `quality/*`, and `episodes/*` are restricted diagnostic outputs. They remain ignored by Git and are not training/public report inputs by default.
   - `selected/*` are the training-facing outputs and must not contain tenant/user/session hashes, `sample_id`, request IDs, file paths, file path hashes, internal task fingerprints, raw text-derived hashes, or raw audit metadata.
   - Reports are operational summaries and must use non-linkable buckets plus k-threshold suppression.
   - Restricted diagnostic directories and temp/spool directories must be created through the existing safe path/atomic write layer with symlink checks, sensitivity classification in the manifest, and POSIX owner-only permissions where supported. Preflight rejects world-readable restricted directories when permission checks are available.
   - Add `schema_version` to all new outputs and reports.
   - Keep legacy raw export schemas for `sft/*`, `tool_use_sft/*`, and `router_classification/*` accepted by existing tests/consumers. Add compatibility tests proving their required fields and semantics are unchanged.
   - Extend `canonical/*` with top-level `task` and richer `quality`; bump canonical schema version in manifest.
   - Add `selection_manifest` with schema versions, output matrix, config values, selection mode, labeler flags, run ID, disk/memory limits, and sensitivity classification.

3. Extend canonical records safely:
   - Add `task.route_label`, `task.intent_label`, internal `task.task_fingerprint_internal`, optional `task.episode_id_internal`, and `task.turn_index`.
   - Add export-safe `task.task_bucket` only as a coarse route/intent bucket or keyed date-scoped bucket that cannot be reversed to text and is suppressed from reports when count is below k. Date-scoped HMAC buckets require a local `AUDIT_SELECTION_HMAC_KEY`; never reuse provider/API keys. If no local selection key is configured, omit HMAC task buckets from selected outputs/reports and fall back to coarse route/intent buckets.
   - Extend `quality` with `deterministic_quality_score`, optional `model_quality_score`, `final_quality_score`, `value_labels`, `risk_labels`, `reject_reasons`, `use_for`, duplicate/quota labels, and selection-safe metadata.
   - Add ordering fields in `source`: `event_time`, `event_time_ms`, and `index_order`. Prefer raw `timestamp_ms`, then parse raw `timestamp`, then fall back to index order.
   - Define `index_order` as a stable tuple derived from date partition, index line number, and detail-file sequence within that index. Only use index ordering for grouping within the same date partition; mark records/episodes with `index_order_only` when real event time is unavailable.

4. Phase 1: quality scoring and selected single-turn exports.
   - Add deterministic hard filters for greeting/probe-only inputs, too-short inputs without actionable intent, empty user text, empty-after-redaction content, low-information assistant replies, redaction risk, invalid tool traces, incomplete length responses, exact duplicates, and export-specific duplicates.
   - Add deterministic intent labels, value labels, risk labels, additive deterministic quality scoring, and hard-reject override.
   - Duplicate keys are export-specific and internal only:
     - Router duplicate key: normalized final user text + route/intent + safe feature bucket.
     - SFT duplicate key: normalized final user text + assistant response hash + route/intent.
     - Tool-use duplicate key: normalized final user text + tool-name set + tool-call argument hash bucket.
     - Episode duplicate key: ordered task fingerprints + response hashes + tool-name sequence.
   - Duplicate key values, response hashes, argument hash buckets, and internal stable tie-breakers must never be serialized into selected outputs, reports, label queues, manifests, or external model payloads. Only aggregate counts and reason codes may be emitted.
   - Add user-day and task-fingerprint quota controls. Before quota application, apply stable ranking: hard safety pass, deterministic score descending, high-value label priority, event time or index order ascending, then internal stable ID tie-breaker.
   - Internal stable ID tie-breakers may use existing canonical `sample_id` or a keyed HMAC, but must never appear in selected outputs, reports, label queues, or external model payloads.
   - Keep old raw exports unfiltered for backward compatibility; apply hard rejects, score thresholds, duplicate suppression, and quotas only to `selected/*`.
   - Produce `quality/YYYY-MM-DD.jsonl`, `selected/sft/YYYY-MM-DD.jsonl`, `selected/tool_use_sft/YYYY-MM-DD.jsonl`, `selected/router_classification/YYYY-MM-DD.jsonl`, `reports/YYYY-MM-DD.quality_stats.json`, `reports/YYYY-MM-DD.user_task_stats.json`, and `reports/YYYY-MM-DD.selection_manifest.json`.
   - `quality/*` may include sanitized diagnostics for hard-rejected samples, but records rejected for redaction risk or empty-after-redaction must omit text fields entirely and keep only reason codes, score metadata, and non-linkable aggregate features.

5. Define the selected-output privacy schema:
   - Selected records may include training content required by the target task, `schema_version`, source date, coarse model bucket or omitted model, score bucket or bounded score metadata, allowed value/risk labels, route/intent labels, and export-safe task bucket when k-thresholds allow it.
   - Selected records must not include `sample_id`, tenant/user/session hashes, internal task fingerprints, exact content hashes, file path hashes, request IDs, source index order, or high-cardinality report/debug identifiers.
   - Rare/high-cardinality metadata is omitted or bucketed. For example, model names can be bucketed to model family or omitted; task buckets are emitted only after k-threshold checks.
   - Before selected artifacts are committed, run a selected-output redaction verification pass over training text and metadata. Hard-fail selected export if unresolved secrets, API keys, URLs, emails, phone numbers, government/bank IDs, IPs, file paths, UUID-like IDs, long sensitive literals, unresolved redaction placeholders, or other configured direct identifiers remain.
   - Add tests that selected outputs contain no forbidden fields, no deterministic text-derived fingerprints, and no unresolved PII/secret/path patterns in training text.

6. Phase 2: episode grouping and multi-turn selected export.
   - Build restricted diagnostic `episodes/YYYY-MM-DD.jsonl` from quality-annotated, redacted canonical records.
   - Group primarily inside one internal tenant/user/session scope by `route_label + task_fingerprint_internal`.
   - If `session_hash` is missing, use conservative fallback grouping by non-exported tenant/user scope + internal task fingerprint + short inactivity gap + route/tool/intent stability. Fallback episodes are marked `missing_session_fallback` and are ineligible for `selected/multi_turn_sft` by default.
   - Use a default maximum turn gap of 30 minutes when event time is available.
   - Deterministic continuation predicates: keep turns in the same episode only when all are true: same internal tenant/user scope, same session when present, same route label, same intent label or intent family, same tool-name set unless no tools are involved, same internal task fingerprint or normalized final user text explicitly references prior context with allowlisted continuation terms, and gap <= threshold. Otherwise split.
   - If event time is unavailable or unreliable, group only within one date and one source/index partition, use `index_order`, add `index_order_only`, and keep those episodes out of selected multi-turn training by default.
   - Export `selected/multi_turn_sft/YYYY-MM-DD.jsonl` only for eligible episodes. Selected multi-turn metadata must use ephemeral non-linkable `episode_export_id` and privacy-safe task metadata, not internal episode IDs or tenant/user/session hashes.

7. Define a concrete selected tool-trace validator.
   - Validate pre-redaction tool structure locally before redaction and validate post-redaction exportability after redaction.
   - Valid tool definitions must be OpenAI-compatible function tools with string `name` and JSON-serializable `description`/`parameters` when present.
   - Selected tool-use calls must have non-empty `id`, `type=function`, function name present in provided tool definitions when tools are provided, and `arguments` that parse as a strict JSON object before redaction and remain an exportable strict JSON object after redaction.
   - Legacy raw/canonical diagnostics may accept JSON-array arguments only for compatibility with observed historical data; array arguments are excluded from selected tool-use exports unless a later fixture proves a specific training format needs them.
   - If messages include tool result messages, call IDs must match prior assistant tool calls and preserve order.
   - A selected tool-use sample or episode must not contain hallucinated tool names, malformed JSON arguments, missing required call IDs, or call/result ordering contradictions.
   - Invalid traces may remain in canonical diagnostics but are excluded from selected tool-use exports.

8. Phase 3: optional model-assisted route, intent, and quality labels.
   - Reuse existing `AUDIT_LABEL_BASE_URL`, `AUDIT_LABEL_API_KEY`, `AUDIT_LABEL_MODEL`, and `AUDIT_LABEL_TIMEOUT`.
   - Add explicit `--enable-route-labeler` and `--enable-quality-labeler`. No external model call is allowed unless the relevant flag and complete `AUDIT_LABEL_*` config are both present.
   - Build strict allowlisted payload schemas for both route and quality labeler calls. Payload builders must be covered by regression tests that assert forbidden fields are absent.
   - External labeler payloads are feature-only by default. Redacted/truncated snippets are disabled unless `--enable-label-snippets` is passed, the enabled run is documented in the manifest, and the local leakage scan passes. This preserves the synthetic/feature-only safety posture unless there is explicit approval for snippet use.
   - Do not send `sample_id`, request IDs, file paths or file path hashes, tenant/user/session hashes, internal task fingerprints, export task buckets, API keys, IPs, raw request bodies, raw response bodies, raw audit records, raw metadata, weak model labels, or unapproved snippets.
   - Free-text snippets are allowed only after redaction, truncation, and a local leakage scan passes. If the leakage scan fails, skip the model call and degrade to rule-only.
   - Concrete leakage scan rejects snippets with: secrets/API-key patterns, URLs, emails, phone numbers, government/bank IDs, IPs, absolute or relative file paths, UUID-like IDs, long base64/hex/alphanumeric literals, code blocks or code-heavy text above a small threshold, stack traces, proprietary-looking long literals, high redaction density, unresolved redaction placeholders only, or length above `--label-max-input-chars`. Tests must include negative fixtures for each reject rule.
   - Route payload includes only redacted/truncated final user text when allowed, lightweight features, tool-name set, and allowed route labels.
   - Quality payload includes only redacted/truncated final user and assistant snippets when allowed, route/intent features, tool-name set, message counts, token buckets, redaction density bucket, allowed intent/value/risk labels, and response format.
   - Model output may suggest `route_label`, `intent_label`, `quality_score`, `value_labels`, `risk_labels`, and `reason`. It cannot write `use_for` directly or override hard rejects, duplicate suppression, quota limits, invalid schema, or redaction risk.
   - Positive model score adjustments cannot auto-select a record that failed deterministic threshold eligibility. They are recorded for review/reporting. Negative model risk can downrank or remove selection eligibility if it adds an allowed risk label. Record deterministic score, model suggested score, final score, and selection reason separately.
   - Malformed, timed-out, invalid, or low-confidence responses degrade to rule-only output and write only feature-level, audit-safe reason codes.

9. Define safe label queue and report schemas.
   - Label queue records must be feature-only: no snippets, no `sample_id`, no tenant/user/session hashes, no internal task fingerprints, no task buckets, no file paths, and no raw identifiers. Use ephemeral queue IDs plus route/intent/features/reason codes.
   - Apply k-thresholding to every emitted report bucket combination, including score/value/risk/route/intent/model/task combinations. Buckets below k are suppressed or merged into `suppressed_small_count`.
   - `user_task_stats` must not expose per-user hashes or highly granular behavioral fingerprints. Aggregate by route/intent/score buckets and suppress or bucket small counts below k, default k=5.
   - Reports may include task bucket counts only when counts pass k and the bucket cannot be tied to a user/session in the report.
   - Selected outputs must not include tenant/user/session hashes. Use ephemeral export IDs only when needed and ensure those IDs are not stable across public/report surfaces.

10. Add CLI/config controls with safe defaults and exact output matrix:
   - Default mode writes legacy raw outputs plus new quality, selected, episodes, and reports.
   - `--disable-selection` disables `quality/*`, `selected/*`, `episodes/*`, and selection reports; legacy raw outputs continue.
   - `--disable-episodes` disables `episodes/*` and `selected/multi_turn_sft/*` but keeps Phase 1 quality/selected single-turn outputs.
   - `--disable-diagnostics` suppresses restricted diagnostic artifacts (`canonical/*`, `quality/*`, `episodes/*`) while still allowing internal quality/episode computation needed for selected outputs and reports.
   - `--compat-output-set` is an alias for legacy-only output and conflicts with `--enable-quality-labeler`, `--disable-selection=false` style future flags, or any selected-output-only option. If both `--compat-output-set` and `--disable-episodes` are present, compat wins and episodes remain disabled.
   - `--enable-route-labeler` controls route model calls; `--enable-quality-labeler` controls quality model calls.
   - `--enable-label-snippets` permits redacted/truncated snippet fields in external model payloads only when a route or quality labeler is also enabled and the leakage scan passes. Without this flag, labeler calls use feature-only payloads.
   - Add scoring thresholds: `--selected-min-score`, `--router-min-score`, `--sft-min-score`, `--tool-use-min-score`, `--multi-turn-min-score`.
   - Add quotas: `--max-selected-sft-per-user-per-day`, `--max-selected-router-per-user-per-day`, `--max-selected-tool-use-per-user-per-day`, `--max-selected-per-task-fingerprint-per-day`, `--max-high-value-per-task-fingerprint-per-day`.
   - Add label/input and selection memory controls: `--label-max-input-chars`, `--max-in-memory-samples`, `--max-selection-memory-mb`, and `--selection-mode auto|in-memory|spool`.
   - Reject invalid new CLI values and conflicting flag combinations with `SystemExit`; do not silently clamp selection controls. Record effective config and output matrix in `selection_manifest`.
   - Document expected new output files and disk/runtime implications in README.

11. Add preflight validation, memory protection, and automatic spool fallback.
   - Before writing final artifacts, preflight the configured output matrix, schema validators, report k-threshold config, selected-output privacy schema, labeler flags, lock availability, and estimated disk/temp paths.
   - Default `selection-mode=auto` starts in memory and switches to spool before retaining a record when conservative estimated memory or sample thresholds would be exceeded.
   - Estimate retained size before appending objects using strict JSON byte length plus a conservative multiplier; sample-count caps remain a hard stop.
   - In-memory state stores only redacted canonical records and lightweight selection views, never raw audit details.
   - Use a unique run ID and per-date lock file under `.tmp/locks` so concurrent runs for the same date/output root cannot clobber `.tmp`, spool, or final outputs.
   - Locks use atomic create-only semantics with PID, hostname, run ID, start time, and configured date/output root metadata. Stale-lock handling must be deterministic: if the PID is alive on the same host, fail closed; if the process is gone or the lock is older than a documented TTL, quarantine or remove only after validating the run-specific temp path belongs to that stale lock. Cover active-lock and stale-lock cases in tests.
   - Spool mode writes redacted canonical/quality views and selection views under a run-specific `.tmp/<date>.<run_id>/selection_spool/` path, then performs a second pass to build selected outputs and episodes.
   - Startup preflight scans for abandoned run-specific temp/spool directories for the same output root and date after lock validation. It cleans only temp directories proven to belong to inactive stale runs and never touches final outputs.
   - If spool writing, spool reading, strict JSON validation, or lock acquisition fails, fail closed according to the selected commit mode.
   - Commit mode is all-or-nothing by default for the configured output matrix. Operators can use `--disable-selection` or `--compat-output-set` for legacy-only recovery.
   - `dry-run` must exercise the same preflight and memory/spool decision path and remove spool/temp files on success and failure. No debug mode preserves temp files in this implementation.

12. Preserve atomic output semantics.
   - Extend current atomic write/commit path so every enabled output is committed together under the run ID.
   - No half-written selected, quality, episode, spool, or report files may be visible after failure.
   - Existing path safety, symlink checks, strict JSON writing, and rollback behavior must continue to apply.

13. Add explicit minimal schemas and golden fixtures.
   - Define minimal JSON schemas in tests or test helpers for `quality`, `episodes`, each `selected/*` export, `quality_stats`, `user_task_stats`, `selection_manifest`, label queue, safe label payloads, and output matrix manifests.
   - Add golden fixture dates with expected output snippets for each phase.
   - Keep tests strict JSON parseable with `allow_nan=False` expectations and assert no raw prompts/direct identifiers/internal fingerprints in selected outputs, label queues, external payloads, or reports.
   - Add acceptance tests proving Phase 1 deterministic outputs are byte-stable when both labelers and `--enable-label-snippets` are disabled, and that enabling Phase 3 cannot change hard rejects, duplicate suppression, quota eligibility, or deterministic score fields except through explicitly recorded model-suggestion fields and allowed final-score downranking.

14. Update documentation.
   - Update `audit_training/README.md` to show raw exports versus selected training exports, restricted diagnostic outputs, new schema versions, new CLI flags, exact output matrix, default behavior, compatibility mode, Phase 3 safety switches, memory/spool behavior, output/disk expectations, and safe labeler constraints.
   - Keep `.env` and generated outputs ignored.

## Key decisions & tradeoffs

- Full Phase 1 through Phase 3 is in scope, but implementation and validation must be phased so Phase 1 remains independently usable before episode and model-assist behavior are trusted.
- Implementation stays in the existing script for this pass to avoid combining data-selection risk with package migration risk. Internal interfaces and pure-function sections are required before implementation.
- Canonical, quality, and episodes are restricted diagnostics. Selected outputs are the training-facing artifacts and have stricter privacy schemas.
- Old raw exports remain compatible and mostly unfiltered. Selected exports become the recommended training entrypoint. Compatibility flags provide a legacy-only recovery path.
- Existing `AUDIT_LABEL_*` config is reused for both route and quality labeling, but both route and quality external calls require explicit CLI flags.
- Daily in-memory selection is allowed only with protection. `auto` mode must spill to a run-specific spool before thresholds are exceeded.
- Commit semantics are all-or-nothing for the configured output matrix. This can block legacy outputs when default selected generation fails, but preflight plus compatibility mode reduce operational surprise.
- Episode grouping is conservative. Missing-session or index-order-only episodes are diagnostic by default and not selected for multi-turn training in the first implementation.
- Deterministic hard safety filters, duplicate suppression, and quotas outrank model labels. The model can advise; it cannot upgrade a below-threshold deterministic sample into automatic training selection.
- Reports favor privacy over granularity. K-thresholding applies to every emitted bucket combination.
- Feature-only external labeling is the default even when model labelers are enabled. Allowing redacted snippets requires an additional explicit flag because selected training data and audit snippets can still contain residual sensitive text after normal redaction.

## Risks / open questions

- The actual production audit data may have timestamp variants not represented in current tests. Implementation should accept common fields conservatively and record ordering-risk labels when parsing fails.
- Spool mode adds more I/O, locking, and a second pass. Atomic commit and cleanup must be reviewed carefully so partial outputs are never published.
- Memory estimation in Python is approximate. The implementation should spill proactively and keep hard sample caps rather than pretending to know exact resident memory.
- Intent labels and quality score thresholds are heuristic. Reports and manifests must make broad distributions inspectable while still suppressing small/linkable buckets.
- Tightening route-labeler activation and payload shape can change current optional route-label behavior. This is intentional for safety and must be documented.
- Multi-turn episode grouping can miss valid continuations because the predicates are conservative. This is preferred over merging unrelated tasks.
- Small-count suppression can make debugging harder. Developers can inspect restricted local diagnostics, but training-facing outputs and reports should remain non-linkable.
- Disabling diagnostic artifacts reduces retention risk but can make failure analysis harder. The manifest must record whether diagnostics were written, and tests should cover both default and `--disable-diagnostics` modes.

## Out of scope

- No database is required for this implementation. SQLite, external sort, or a durable state store can be considered after spool-mode limits are observed.
- No embedding-based near-duplicate detection in the first implementation.
- No external model call may receive raw audit records, direct identifiers, hashes that link back to source entities, raw file paths, raw request/response bodies, API keys, IP addresses, deterministic text fingerprints, or unredacted sensitive text.
- No removal of existing raw exports in this change.
- No package/module split unless implementation becomes impossible to test safely inside the current script.
- No debug mode that preserves spool/temp files in the first implementation.
