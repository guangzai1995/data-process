# Plan Review Log: Audit Quality, Task, Episode, and Model-Assisted Selection Pipeline

Act 1 (grill) complete — plan locked with the user. MAX_ROUNDS=5.

## Act 1 decisions

- Scope is Phase 1 through Phase 3, not Phase 1 only.
- Implementation stays in `scripts/audit_training_pipeline.py` with pure-function sections for this pass.
- Phase 1/2 outputs are on by default; Phase 3 quality labeler is explicit opt-in.
- Single-day aggregation may use memory, but must have sample/memory thresholds and automatic spool fallback.
- Episode ordering uses `timestamp_ms`/`timestamp`, falling back to index order with risk labeling.
- Phase 3 reuses `AUDIT_LABEL_*` instead of introducing a second provider config.
- Route and quality labeler payloads must be tightened to avoid `sample_id`, hashes, raw bodies, file paths, and weak model-label leakage.
- Old raw exports remain compatible; quality filtering affects `selected/*`.
- Thresholds, quotas, label truncation, and selection memory controls must have defaults and CLI overrides recorded in manifests.
- Phase 1, Phase 2, and Phase 3 each need independent acceptance checks.

## Round 1 — Codex

Could not inspect `PLAN.md` or repo files: the read-only sandbox failed to start with a local `bwrap`/user-namespace error, and the required escalation was rejected by the approval system. Fix: provide the plan contents here or explicitly approve a read-only filesystem command so I can review the actual files.

VERDICT: REVISE

### Claude's response

No PLAN.md content changes yet. Round 1 did not review the plan because Codex could not inspect files inside its read-only sandbox on this host. I will resume the same Codex thread and embed the locked PLAN.md content directly in the prompt so the next round can review the actual plan while still making no file writes.

## Round 2 — Codex

I could not reload the repo-specific review skill because the sandbox issue remains, so this review is based strictly on the embedded locked plan.

- The plan still allows the existing route labeler to run automatically when `AUDIT_LABEL_*` is complete, which can violate the “no external model unless explicitly enabled” safety posture for users who only intended local processing; fix: add an explicit `--enable-route-labeler` or make route labeling default-off in the same style as quality labeling.
- “Redacted, truncated snippets” are still potentially linkable or sensitive, especially for unique support cases, proprietary prompts, code, incident text, or names missed by redaction; fix: define a strict allowlisted model payload schema with automated leakage tests and omit free-text snippets unless a local PII/sensitive-data scan passes.
- The plan says old raw exports remain “mostly unfiltered” while canonical records are extended with new top-level `task`, `quality`, and `source` fields, but does not specify schema/version compatibility for downstream consumers; fix: add an output schema version and tests proving legacy export records remain accepted by current consumers.
- Duplicate suppression by “exact” and “normalized user-text” risks suppressing distinct tasks with identical user text but different tool context, files, route, or assistant outcome; fix: define duplicate keys per export type and include route/tool/context-safe fingerprints where relevant.
- User-day and task-fingerprint quotas can bias against active users or common high-value tasks without deterministic tie-breaking; fix: specify stable ranking before quota application, for example hard safety first, score descending, event time/index ascending, then sample id hash only if non-exported.
- Episode grouping by `tenant_hash + user_hash + session_hash + route_label + task_fingerprint` conflicts with the rule not to send hashes externally but still bakes linkable hashes into internal selected metadata unless explicitly stripped; fix: state that selected outputs and reports use ephemeral episode IDs and never expose tenant/user/session hashes.
- The `session_hash`-missing fallback using `tenant_hash + user_hash + time_window` can merge unrelated concurrent tasks from the same user; fix: require task fingerprint plus a short inactivity gap and split on route/tool/intent changes, or mark fallback episodes ineligible for training by default.
- Event ordering fallback to `index_order` assumes input file order is meaningful across raw files and shards; fix: define `index_order` as a stable tuple including source file order and record offset, and only group by index within the same source partition.
- “Invalid tool traces” and “valid tool definitions, tool calls, and argument strings” are underspecified and may miss malformed JSON arguments, missing tool results, hallucinated tools, or call/result ordering errors; fix: define a concrete tool-trace validator with required invariants and negative tests.
- Spool mode writes redacted canonical/quality views under `.tmp/selection_spool/<date>.jsonl`, but the plan does not say how concurrent runs for the same date/output dir avoid clobbering each other; fix: put spool and atomic temp outputs under a unique run ID and acquire a per-date lock.
- “Fail closed” on spool failure conflicts with “every old and new output is committed together”: a selection failure could unnecessarily block legacy outputs; fix: explicitly choose either all-or-nothing for the daily run or legacy-only commit with selected outputs marked aborted, and test that behavior.
- Dry-run exercising spool without committing final outputs can still leave `.tmp` spool files containing redacted but sensitive-derived data; fix: require dry-run cleanup of spool files on success/failure and test no temporary data remains unless an explicit debug flag is set.
- Memory accounting is described as approximate but no method is specified for preventing OOM before the threshold check fires; fix: estimate per-record size before appending retained objects and spill proactively with a conservative multiplier.
- Model-assisted `quality_score` bounded to +/-0.15 is underspecified when the deterministic score is near threshold, allowing a model to flip inclusion despite “cannot write use_for”; fix: decide whether model score may affect threshold eligibility and record both deterministic and final eligibility reasons.
- Malformed/timed-out model responses “write audit-safe reasons to reports or label queue,” but label queues themselves can become leakage surfaces; fix: define the label queue schema as feature-only with no snippets or identifiers and include safe-payload regression tests.
- The plan asks for `quality/YYYY-MM-DD.jsonl` from all quality-annotated records, but it is unclear whether rejected records with redaction risk or empty-after-redaction still get exported; fix: export only sanitized diagnostics for rejected records and omit unsafe text fields entirely.
- Reports such as `user_task_stats` can leak behavioral fingerprints even with hashes removed if per-user/task counts are granular; fix: aggregate reports by non-linkable buckets or suppress small counts.
- CLI defaults add quality, episodes, selected outputs to the daily command, which can break automation expecting a fixed output set, runtime, or disk usage; fix: add a compatibility flag or manifest-versioned rollout plan and document expected new files/disk bounds.
- Keeping everything in one large script is a maintainability risk for a three-phase pipeline with atomic I/O, external calls, and grouping logic; fix: at minimum define internal interfaces and testable pure sections before implementation, with no cross-phase hidden global state.
- The plan does not define golden fixtures or expected JSON schemas for every new output, so implementation can satisfy prose while producing inconsistent artifacts; fix: add explicit minimal schemas and fixture-level expected outputs for quality, selected, episodes, reports, and manifest.

VERDICT: REVISE

### Claude's response

Accepted the material safety and operability findings. I will revise PLAN.md to: require explicit route and quality labeler flags, define safe label payload and label-queue schemas, add output schema versions and golden fixtures, strip user/session/tenant hashes from selected outputs/reports, suppress small-count reports, define export-specific duplicate keys and quota ranking, make missing-session fallback episodes non-training by default, define index ordering and tool-trace invariants, add unique run IDs and per-date locks for spool/temp outputs, choose all-or-nothing commit unless selection is disabled, require dry-run spool cleanup, estimate memory before retaining records, prevent model positive score adjustments from auto-selecting records, and document rollout/disk bounds. No substantive Codex finding is rejected in this round.

## Round 3 — Codex

- Prior findings are mostly addressed, but `task_fingerprint` is still treated as safe enough for selected outputs/reports even though it may be deterministic and text-derived; fix: keep text-derived fingerprints internal, or export only keyed/date-scoped non-reversible buckets with small-count suppression.
- The “local leakage scan” gating external snippets is still undefined, making the model-call privacy boundary untestable; fix: specify concrete reject rules for secrets, URLs, emails, IDs, names, code/proprietary text, long literals, and high redaction density, with negative fixtures.
- Selected outputs may include `source date`, `model name`, score metadata, labels, and task fingerprints; combined metadata can still be linkable for rare tasks; fix: define a selected-output privacy schema that suppresses or buckets rare/high-cardinality fields.
- Internal hashes remain in canonical/episode source “when needed for auditability,” but canonical/episodes are default outputs and may be consumed beyond local debugging; fix: explicitly classify canonical/episodes as restricted diagnostics and exclude them from training/public report paths.
- The plan relies on `sample-id hash` as a quota tie-breaker while also banning linkable hashes from outputs, but does not define whether the hash is salted/keyed and run-stable; fix: use an internal keyed HMAC or existing non-exported stable ID and assert it never appears in artifacts.
- Tool-call argument validation only checks parseability after redaction; redaction can make formerly valid arguments invalid or change semantic fields required for training; fix: validate both pre-redaction structure locally and post-redaction exportability, but export only the redacted version.
- All-or-nothing commit semantics can block legacy outputs if report small-count suppression or selected schema validation fails late, increasing operational blast radius; fix: add a preflight validation phase before writing legacy artifacts, or make compatibility mode the documented migration default.
- `--compat-output-set` overlaps ambiguously with `--disable-selection` and `--disable-episodes`; fix: define exact output matrix and conflict handling for every flag combination.
- Episode split rule says split on route/intent/tool/task changes “unless the later turn clearly continues the same task,” which is not deterministic enough for implementation/tests; fix: replace with explicit continuation predicates.
- Reports “make distributions inspectable” while suppressing small counts, but no minimum aggregation level is specified for score/value/risk combinations; fix: apply k-thresholding to every emitted bucket combination, not just user/task stats.

VERDICT: REVISE

### Claude's response

Accepted the remaining privacy and determinism findings. I will revise PLAN.md to keep text-derived task fingerprints and sample IDs internal, classify canonical/episodes as restricted diagnostics, add selected-output privacy schemas and k-thresholding for every report bucket, define the leakage scan with concrete deny rules and fixtures, validate tool arguments before and after redaction, add a preflight validation phase before final output commit, define the exact CLI output matrix and conflicts, and replace ambiguous episode continuation language with explicit deterministic predicates.


## Round 4 — Codex

The Round 3 findings are materially addressed. Remaining issues are narrower but still worth tightening before implementation:

- The external snippet policy still allows redacted free text to leave the environment, which may be unacceptable under the repo’s “synthetic-only unless future written design approves” rule; fix: make external model payloads feature-only by default and require an explicit documented approval flag for any free-text snippet.
- `selected/*` are training-facing but necessarily contain redacted prompt/response content, so “privacy-safe” field bans do not cover residual PII in training text; fix: add selected-output redaction verification and hard-fail selected export on unresolved PII/secrets/path patterns.
- `canonical/*`, `quality/*`, and `episodes/*` are called restricted diagnostics, but the plan does not say how restriction is enforced beyond Git ignore; fix: write them only under a clearly restricted output root or manifest classification plus permissions checks where the current pipeline supports it.
- `task_bucket` can be a keyed date-scoped bucket, but key management/rotation is unspecified; fix: define it as run-local or date-local non-exported unless a configured local secret is present, and never reuse provider/API keys for HMAC.
- Duplicate keys use assistant response hashes and tool argument hash buckets internally; if logs or manifests include duplicate labels with key material, they can leak content-derived identifiers; fix: assert duplicate key values are never serialized, only reason codes/counts.
- Locking under `.tmp/locks` is underspecified for stale locks and process crashes; fix: use atomic lock creation with PID/run metadata, stale-lock detection rules, and tests for lock cleanup/failure.
- Spool files contain restricted redacted diagnostics but may persist after crashes despite dry-run cleanup guarantees; fix: add startup cleanup for abandoned run-specific temp dirs after lock validation.
- The selected tool validator permits arguments that parse as JSON arrays, but OpenAI function-call arguments are conventionally JSON objects; fix: require objects for function tool calls unless existing legacy data proves arrays must be supported and tests cover that compatibility.
- The default mode writes restricted diagnostic outputs plus training outputs, increasing disk and retention risk; fix: document retention expectations and add a `--selected-only` or diagnostics-disable option if operators do not need local diagnostics.
- Golden fixtures are planned, but no acceptance gate says Phase 3 cannot regress Phase 1 deterministic selection; fix: add tests that Phase 1 outputs are byte-stable when both labelers are disabled.

VERDICT: REVISE

### Claude's response

Accepted the material findings and tightened PLAN.md accordingly. Changes made: external labeler payloads are now feature-only by default; redacted snippets require explicit `--enable-label-snippets` plus manifest recording and leakage-scan pass; selected exports get a second redaction verification gate with hard failure on unresolved PII/secret/path patterns; restricted diagnostic directories require safe-path checks, sensitivity classification, and owner-only permissions where available; HMAC task buckets require a dedicated local `AUDIT_SELECTION_HMAC_KEY` and never reuse provider keys; duplicate key material is internal-only and never serialized; locks now require atomic create-only semantics, PID/run metadata, stale-lock rules, and tests; startup preflight cleans only proven inactive run-specific temp/spool dirs; selected tool-use arguments must be JSON objects, while legacy array arguments remain diagnostic-only unless later fixtures justify selected support; `--disable-diagnostics` and `--enable-label-snippets` are added to the CLI matrix; acceptance tests now require Phase 1 byte stability when labelers/snippets are disabled and constrain Phase 3 to explicit model-suggestion/downranking fields. No Round 4 finding is rejected.


## Round 5 — Codex

No material implementation-blocking issues remain. The Round 4 blockers are addressed with feature-only external labeling by default, selected-output redaction verification, restricted diagnostic handling, HMAC key rules, non-serialization of internal hashes, deterministic locking/stale cleanup, stricter tool argument validation, diagnostics-disable support, and byte-stability acceptance tests.

Residual risks remain in heuristic quality scoring, conservative episode grouping, and operational complexity around spool/atomic commit, but the plan now names explicit safeguards and tests rather than leaving contradictions or privacy holes open.

VERDICT: APPROVED

### Claude's response

Accepted. The plan is now converged after 5 Codex review rounds. No implementation code has been written during the grill/review flow; next step requires user sign-off on whether Codex builds from `PLAN.md`, Claude implements directly, or we stop at the approved plan.
