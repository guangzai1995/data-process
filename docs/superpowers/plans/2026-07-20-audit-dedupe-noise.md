# Audit Dedupe and Debug-Noise Suppression 实现计划

> **面向 AI 代理的工作者：** 必需子技能：使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务实现此计划。步骤使用复选框（`- [ ]`）语法来跟踪进度。

**目标：** 在 audit training pipeline 的 selected 训练出口前增加确定性、内存有界的重复数据与调试噪声过滤。

**架构：** 在现有 canonical/quality 层之后、selected export 之前新增 `DedupeState`。它为每条 canonical 样本计算不可逆 hash/signature，标注 exact duplicate、normalized duplicate、near duplicate、debug repeat 和 debug burst，并通过 `reject_reasons` 清空 selected eligibility。raw/canonical/legacy/quality 诊断继续保留，`selected/*` 默认过滤。

**技术栈：** Python 标准库、现有 `unittest` 测试、现有 JSONL pipeline、无外部模型、无新第三方依赖。

---

## 文件结构

- 修改：`scripts/audit_training_pipeline.py`
  - 新增 dedupe normalization、SimHash、状态管理、标注函数。
  - 扩展 `RISK_LABELS`、`default_selection_config`、report state、manifest、CLI 参数。
  - 将 dedupe 注入 in-memory 和 spool selection 路径。
- 修改：`tests/test_audit_training_pipeline.py`
  - 新增 `SelectionDedupeTest`，覆盖单元与集成行为。
  - 扩展 CLI、README、report、spool 相关测试。
- 修改：`audit_training/README.md`
  - 记录默认去重行为、禁用开关、报告字段和隐私边界。

## 实现顺序

先落基础函数和状态，再接入 selected 过滤，最后接入 spool/report/CLI。每个任务后提交一次，避免大块变更难审。

### 任务 1：Dedupe 基础签名与状态

**文件：**
- 修改：`scripts/audit_training_pipeline.py:268-321`
- 修改：`scripts/audit_training_pipeline.py:660-670`
- 测试：`tests/test_audit_training_pipeline.py`

- [ ] **步骤 1：编写失败的 normalization 与 SimHash 测试**

在 `tests/test_audit_training_pipeline.py` 的 `SelectionPipelineTest` 后新增类：

```python
class SelectionDedupeTest(unittest.TestCase):
    def test_normalize_for_dedupe_replaces_numbers_paths_urls_and_placeholders(self):
        pipeline = load_pipeline_module()
        text = "  请修复 /tmp/app-123.py 第 42 行，见 https://example.com/a?id=9 <SECRET_1>  "
        normalized = pipeline.normalize_for_dedupe(text)
        self.assertEqual(
            normalized,
            "请修复 <path> 第 <num> 行 见 <url> <redacted>",
        )

    def test_simhash_helpers_are_stable_and_measure_distance(self):
        pipeline = load_pipeline_module()
        left = pipeline.simhash64(["python", "报错", "修复"])
        right = pipeline.simhash64(["python", "报错", "修复"])
        other = pipeline.simhash64(["发票", "订单", "查询"])
        self.assertEqual(left, right)
        self.assertEqual(pipeline.hamming_distance64(left, right), 0)
        self.assertGreater(pipeline.hamming_distance64(left, other), 0)
```

- [ ] **步骤 2：运行测试验证失败**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_normalize_for_dedupe_replaces_numbers_paths_urls_and_placeholders tests.test_audit_training_pipeline.SelectionDedupeTest.test_simhash_helpers_are_stable_and_measure_distance -v
```

预期：FAIL，报错包含 `module 'audit_training_pipeline' has no attribute 'normalize_for_dedupe'`。

- [ ] **步骤 3：添加基础常量和 helper**

在 `RISK_LABELS` 中加入：

```python
    "near_duplicate",
    "debug_noise",
    "debug_burst",
    "dedupe_state_saturated",
```

在 `CONTINUATION_TERMS` 后加入：

```python
DEDUPE_REDACTION_RE = re.compile(r"<[A-Z_]+_\d+>")
DEDUPE_URL_RE = re.compile(r"(?i)\bhttps?://\S+")
DEDUPE_PATH_RE = re.compile(r"(?:(?:^|\s)(?:/|\.\.?/|~[/\\]|[A-Za-z]:[\\/])[^\s]+|[\w.\-]+(?:/|\\)[\w.\-/\\]+)")
DEDUPE_NUMBER_RE = re.compile(r"(?<!\w)\d+(?:\.\d+)?(?!\w)")
DEDUPE_PUNCT_RE = re.compile(r"[，。！？；：、,.!?;:()\[\]{}\"'`]+")
DEBUG_CONTROL_TEXTS = set([
    "continue", "retry", "again", "test", "ok", "yes", "no", "a", "b", "<num>", "1", "2",
    "继续", "重试", "再来", "测试", "不对", "好的", "可以", "嗯", "是", "否",
])
DEDUPE_REJECT_REASONS = set([
    "duplicate_content",
    "normalized_duplicate_content",
    "near_duplicate_content",
    "debug_noise_repeat",
    "debug_burst",
])
```

在 `normalize_text` 后新增：

```python
def normalize_for_dedupe(text, max_chars=1200):
    text = normalize_text(text)
    if not text:
        return ""
    text = DEDUPE_REDACTION_RE.sub(" <redacted> ", text)
    text = DEDUPE_URL_RE.sub(" <url> ", text)
    text = DEDUPE_PATH_RE.sub(" <path> ", text)
    text = DEDUPE_NUMBER_RE.sub(" <num> ", text)
    text = DEDUPE_PUNCT_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    tokens = text.split()
    collapsed = []
    for token in tokens:
        if collapsed and collapsed[-1] == token and token in DEBUG_CONTROL_TEXTS:
            continue
        collapsed.append(token)
    return " ".join(collapsed)[:max_chars]


def dedupe_tokens(text):
    normalized = normalize_for_dedupe(text)
    tokens = normalized.split()
    grams = []
    compact = normalized.replace(" ", "")
    for index in range(max(0, len(compact) - 2)):
        grams.append(compact[index:index + 3])
    return tokens + grams


def simhash64(tokens):
    weights = [0] * 64
    for token in tokens:
        digest = int(hashlib.sha256(str(token).encode("utf-8")).hexdigest()[:16], 16)
        for bit in range(64):
            weights[bit] += 1 if digest & (1 << bit) else -1
    value = 0
    for bit, weight in enumerate(weights):
        if weight >= 0:
            value |= (1 << bit)
    return value


def hamming_distance64(left, right):
    return int(left ^ right).bit_count()


def jaccard_similarity(left_tokens, right_tokens):
    left = set(left_tokens)
    right = set(right_tokens)
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return float(len(left & right)) / float(len(left | right))
```

- [ ] **步骤 4：运行基础测试验证通过**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_normalize_for_dedupe_replaces_numbers_paths_urls_and_placeholders tests.test_audit_training_pipeline.SelectionDedupeTest.test_simhash_helpers_are_stable_and_measure_distance -v
```

预期：2 个测试 PASS。

- [ ] **步骤 5：添加 DedupeState 初始化测试**

继续在 `SelectionDedupeTest` 加：

```python
    def test_init_dedupe_state_uses_bounded_collections(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(max_dedupe_seen_hashes=3)
        state = pipeline.init_dedupe_state(config)
        self.assertEqual(state["max_seen_hashes"], 3)
        self.assertIn("router_classification", state["seen"])
        self.assertEqual(state["dedupe_counts"], {})
        self.assertEqual(state["risk_counts"], {})
```

- [ ] **步骤 6：运行状态测试验证失败**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_init_dedupe_state_uses_bounded_collections -v
```

预期：FAIL，报错包含 `init_dedupe_state` 不存在或 config key 不存在。

- [ ] **步骤 7：添加 config 默认值和状态函数**

在 `default_selection_config` 中加入：

```python
        "enable_dedupe": True,
        "enable_near_duplicate_dedupe": True,
        "enable_debug_noise_filter": True,
        "near_duplicate_simhash_hamming": 4,
        "near_duplicate_min_chars": 16,
        "near_duplicate_min_tokens": 4,
        "near_duplicate_jaccard": 0.88,
        "max_near_duplicate_representatives_per_bucket": 128,
        "max_debug_control_repeats_per_session": 2,
        "max_debug_task_burst_per_session": 8,
        "debug_burst_window_minutes": 20,
        "max_dedupe_seen_hashes": 1000000,
        "max_dedupe_user_session_windows": 100000,
        "max_near_duplicate_buckets": 50000,
```

在 report helper 前新增：

```python
def init_dedupe_state(config):
    return {
        "seen": {"router_classification": set(), "sft": set(), "tool_use_sft": set()},
        "prompt_by_bucket": {},
        "representatives": {},
        "session_control_counts": {},
        "session_task_times": {},
        "dedupe_counts": {},
        "risk_counts": {},
        "max_seen_hashes": config.get("max_dedupe_seen_hashes", 1000000),
    }


def add_unique_list_value(values, value):
    if value not in values:
        values.append(value)
    return values


def add_dedupe_count(state, name):
    add_count(state["dedupe_counts"], name)


def add_dedupe_risk(state, name):
    add_count(state["risk_counts"], name)
```

- [ ] **步骤 8：运行任务 1 测试**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest -v
```

预期：已添加的 3 个测试 PASS。


- [ ] **Step 9: Add state cap saturation test**

Add this test to `SelectionDedupeTest`:

```python
    def test_dedupe_state_caps_mark_saturated_without_crashing(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(max_near_duplicate_representatives_per_bucket=0)
        raw = sample_success_record()
        raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 脚本读取 jsonl 文件并统计每个用户调用次数"}]
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        annotated = pipeline.annotate_task_and_quality(canonical, config)
        state = pipeline.init_dedupe_state(config)
        pipeline.apply_dedupe_annotation(annotated, config, state)
        self.assertIn("dedupe_state_saturated", annotated["quality"]["risk_labels"])
        self.assertNotIn("near_duplicate_content", annotated["quality"]["reject_reasons"])
```

- [ ] **Step 10: Implement bounded-state saturation behavior**

Add a helper near `mark_dedupe_saturated`:

```python
def can_add_state_key(mapping, key, max_keys, canonical, state):
    if key in mapping:
        return True
    if len(mapping) < max_keys:
        return True
    mark_dedupe_saturated(canonical, state)
    return False
```

Use it before creating new representative buckets and session counter buckets. Saturation must add `dedupe_state_saturated` but must not by itself add a hard reject reason.

- [ ] **Step 11: Run state cap test**

Run:

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_dedupe_state_caps_mark_saturated_without_crashing -v
```

Expected: PASS.

- [ ] **Step 12: Commit**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "feat: add audit dedupe primitives"
```

### 任务 2：Exact 和 normalized duplicate 过滤

**文件：**
- 修改：`scripts/audit_training_pipeline.py:2194-2284`
- 修改：`scripts/audit_training_pipeline.py:2699-2704`
- 测试：`tests/test_audit_training_pipeline.py`

- [ ] **步骤 1：编写 exact duplicate 集成失败测试**

在 `SelectionDedupeTest` 加：

```python
    def test_exact_selected_duplicate_is_filtered_from_selected_but_kept_in_legacy_and_quality(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            for index in range(2):
                raw = sample_success_record()
                raw["request_id"] = "request-%d" % index
                raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 代码打印 hello"}]
                raw["response_body"]["choices"][0]["message"]["content"] = "print('hello')"
                write_json(day / "u" / "s" / ("%03d.json" % index), raw)
            write_index(day, [
                {"request_id": "request-0", "file_path": "2026-07-15/u/s/000.json"},
                {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            ])

            pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

            legacy = read_jsonl(output_root / "sft" / "2026-07-15.jsonl")
            selected = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertEqual(len(legacy), 2)
            self.assertEqual(len(selected), 1)
            self.assertTrue(any("duplicate_content" in row["reject_reasons"] for row in quality))
            self.assertTrue(any("duplicate" in row["quality"]["risk_labels"] for row in quality))
```

- [ ] **步骤 2：运行测试验证失败**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_exact_selected_duplicate_is_filtered_from_selected_but_kept_in_legacy_and_quality -v
```

预期：FAIL，`duplicate_content` 不在 quality reject reasons 中。

- [ ] **步骤 3：实现 signature 和 hard reject helper**

在 `selected_duplicate_key` 前新增：

```python
def dedupe_signature_for(kind, canonical):
    text = normalize_for_dedupe(last_user_content(canonical.get("request", {}).get("messages") or []))
    response = normalize_for_dedupe(extract_text_content(canonical.get("response", {}).get("message", {}).get("content")))
    route = canonical.get("task", {}).get("route_label")
    intent = canonical.get("task", {}).get("intent_label")
    if kind == "sft":
        return content_hash({"text": text, "response": response, "route": route, "intent": intent})
    if kind == "tool_use_sft":
        return content_hash({"text": text, "tools": sorted(tool_name_set(canonical)), "route": route, "intent": intent})
    return content_hash({"text": text, "route": route, "intent": intent})


def dedupe_bucket(canonical):
    task = canonical.get("task", {})
    quality = canonical.get("quality", {})
    return "%s:%s:%s" % (
        task.get("route_label") or "unknown",
        task.get("intent_label") or "unknown",
        quality.get("score_bucket") or "unknown",
    )


def mark_dedupe_reject(canonical, state, reason, risk):
    quality = canonical.setdefault("quality", {})
    add_unique_list_value(quality.setdefault("reject_reasons", []), reason)
    add_unique_list_value(quality.setdefault("risk_labels", []), risk)
    quality["use_for"] = []
    add_dedupe_count(state, reason)
    add_dedupe_risk(state, risk)
```

- [ ] **步骤 4：实现 selected kind exact dedupe**

在 `build_selected_outputs` 前新增：

```python
def apply_dedupe_annotation(canonical, config, state):
    quality = canonical.setdefault("quality", {})
    text = normalize_for_dedupe(last_user_content(canonical.get("request", {}).get("messages") or []))
    response = normalize_for_dedupe(extract_text_content(canonical.get("response", {}).get("message", {}).get("content")))
    tokens = dedupe_tokens(text)
    simhash_value = simhash64(tokens) if tokens else 0
    quality["dedupe"] = {
        "prompt_hash": content_hash(text)[:24],
        "response_hash": content_hash(response)[:24],
        "prompt_response_hash": content_hash({"text": text, "response": response})[:24],
        "task_signature_hash": content_hash({
            "task": canonical.get("task", {}).get("task_fingerprint_internal"),
            "route": canonical.get("task", {}).get("route_label"),
            "intent": canonical.get("task", {}).get("intent_label"),
            "tools": sorted(tool_name_set(canonical)),
        })[:24],
        "simhash64": "%016x" % simhash_value,
        "bucket": dedupe_bucket(canonical),
        "decision": "selected_candidate",
        "matched_reason": None,
    }
    if not config.get("enable_dedupe", True) or quality.get("reject_reasons"):
        return canonical
    for kind in ("router_classification", "sft", "tool_use_sft"):
        if kind not in quality.get("use_for", []):
            continue
        key = selected_duplicate_key(kind, canonical)
        if key in state["seen"][kind]:
            quality["dedupe"]["decision"] = "rejected"
            quality["dedupe"]["matched_reason"] = "duplicate_content"
            mark_dedupe_reject(canonical, state, "duplicate_content", "duplicate")
            return canonical
        if len(state["seen"][kind]) < state["max_seen_hashes"]:
            state["seen"][kind].add(key)
        else:
            mark_dedupe_saturated(canonical, state)
    return canonical
```

同时新增 saturation helper：

```python
def mark_dedupe_saturated(canonical, state):
    quality = canonical.setdefault("quality", {})
    add_unique_list_value(quality.setdefault("risk_labels", []), "dedupe_state_saturated")
    add_dedupe_count(state, "state_saturated")
    add_dedupe_risk(state, "dedupe_state_saturated")
```

- [ ] **步骤 5：接入 in-memory selection**

修改 `build_selected_outputs`：

```python
def apply_dedupe_annotations_to_records(annotated_records, config):
    state = init_dedupe_state(config)
    for canonical in sorted(annotated_records, key=selection_rank_key):
        apply_dedupe_annotation(canonical, config, state)
        refresh_selection_use_for(canonical, config)
    return state


def build_selected_outputs(annotated_records, episodes, config):
    state = init_selected_export_state()
    for canonical in sorted(annotated_records, key=selection_rank_key):
        consider_selected_record(canonical, config, state)
    ...
```

然后在 `process_date` 的 in-memory 分支中，在 `build_episodes` 前调用：

```python
                apply_dedupe_annotations_to_records(annotated_records, config)
                episodes = build_episodes(annotated_records, config)
                selected_outputs = build_selected_outputs(annotated_records, episodes, config)
```

- [ ] **步骤 6：运行 exact duplicate 测试验证通过**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_exact_selected_duplicate_is_filtered_from_selected_but_kept_in_legacy_and_quality -v
```

预期：PASS。

- [ ] **步骤 7：编写 normalized duplicate 测试**

在 `SelectionDedupeTest` 加：

```python
    def test_normalized_duplicate_with_number_variation_is_filtered(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            prompts = ["请修复第 42 行 Python 报错", "请修复第 43 行 Python 报错"]
            for index, prompt in enumerate(prompts):
                raw = sample_success_record()
                raw["request_id"] = "request-%d" % index
                raw["request_body"]["messages"] = [{"role": "user", "content": prompt}]
                raw["response_body"]["choices"][0]["message"]["content"] = "可以检查异常栈并修复参数。"
                write_json(day / "u" / "s" / ("%03d.json" % index), raw)
            write_index(day, [
                {"request_id": "request-0", "file_path": "2026-07-15/u/s/000.json"},
                {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            ])

            pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            selected = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            self.assertEqual(len(selected), 1)
            self.assertTrue(any("normalized_duplicate_content" in row["reject_reasons"] for row in quality))
```

- [ ] **步骤 8：实现 normalized prompt-response set**

在 `init_dedupe_state` 加：

```python
        "normalized": {"router_classification": set(), "sft": set(), "tool_use_sft": set()},
```

在 `apply_dedupe_annotation` 的 exact check 后加入：

```python
        normalized_key = dedupe_signature_for(kind, canonical)
        if normalized_key in state["normalized"][kind]:
            quality["dedupe"]["decision"] = "rejected"
            quality["dedupe"]["matched_reason"] = "normalized_duplicate_content"
            mark_dedupe_reject(canonical, state, "normalized_duplicate_content", "duplicate")
            return canonical
        if len(state["normalized"][kind]) < state["max_seen_hashes"]:
            state["normalized"][kind].add(normalized_key)
        else:
            mark_dedupe_saturated(canonical, state)
```

Exact duplicate uses existing `selected_duplicate_key`; normalized duplicate uses new `dedupe_signature_for`. This keeps exact duplicate and number/path/URL/redaction-placeholder duplicate reasons distinct.

- [ ] **步骤 9：运行任务 2 测试**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_exact_selected_duplicate_is_filtered_from_selected_but_kept_in_legacy_and_quality tests.test_audit_training_pipeline.SelectionDedupeTest.test_normalized_duplicate_with_number_variation_is_filtered -v
```

预期：2 个测试 PASS。

- [ ] **步骤 10：Commit**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "feat: filter exact audit training duplicates"
```

### 任务 3：Near duplicate 与调试噪声过滤

**文件：**
- 修改：`scripts/audit_training_pipeline.py`
- 测试：`tests/test_audit_training_pipeline.py`

- [ ] **步骤 1：编写 near duplicate 测试**

在 `SelectionDedupeTest` 加：

```python
    def test_near_duplicate_prompt_in_same_bucket_is_filtered(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            prompts = [
                "请帮我写一个 Python 脚本读取 jsonl 文件并统计每个用户的调用次数",
                "帮我写 Python 脚本读取 jsonl 并统计每个用户调用次数",
            ]
            for index, prompt in enumerate(prompts):
                raw = sample_success_record()
                raw["request_id"] = "request-%d" % index
                raw["request_body"]["messages"] = [{"role": "user", "content": prompt}]
                raw["response_body"]["choices"][0]["message"]["content"] = "可以用 json.loads 逐行读取并用 dict 计数。"
                write_json(day / "u" / "s" / ("%03d.json" % index), raw)
            write_index(day, [
                {"request_id": "request-0", "file_path": "2026-07-15/u/s/000.json"},
                {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            ])

            pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertTrue(any("near_duplicate_content" in row["reject_reasons"] for row in quality))
            self.assertTrue(any("near_duplicate" in row["quality"]["risk_labels"] for row in quality))
```

- [ ] **步骤 2：运行 near duplicate 测试验证失败**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_near_duplicate_prompt_in_same_bucket_is_filtered -v
```

预期：FAIL，没有 `near_duplicate_content`。

- [ ] **步骤 3：实现 near duplicate representative 检查**

在 `apply_dedupe_annotation` 中 exact/normalized 检查后加入：

```python
    if config.get("enable_near_duplicate_dedupe", True):
        min_chars = config.get("near_duplicate_min_chars", 16)
        min_tokens = config.get("near_duplicate_min_tokens", 4)
        if len(text) >= min_chars and len(text.split()) >= min_tokens:
            bucket = quality["dedupe"]["bucket"]
            reps = state["representatives"].setdefault(bucket, [])
            for rep_hash, rep_tokens in reps:
                if hamming_distance64(simhash_value, rep_hash) <= config.get("near_duplicate_simhash_hamming", 4):
                    if jaccard_similarity(tokens, rep_tokens) >= config.get("near_duplicate_jaccard", 0.88):
                        quality["dedupe"]["decision"] = "rejected"
                        quality["dedupe"]["matched_reason"] = "near_duplicate_content"
                        mark_dedupe_reject(canonical, state, "near_duplicate_content", "near_duplicate")
                        return canonical
            cap = config.get("max_near_duplicate_representatives_per_bucket", 128)
            if len(reps) < cap:
                reps.append((simhash_value, tokens))
            else:
                mark_dedupe_saturated(canonical, state)
```

- [ ] **步骤 4：运行 near duplicate 测试验证通过**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_near_duplicate_prompt_in_same_bucket_is_filtered -v
```

预期：PASS。

- [ ] **步骤 5：编写不同 bucket 不误杀测试**

在 `SelectionDedupeTest` 加：

```python
    def test_similar_prompt_in_different_route_bucket_is_not_near_duplicate(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config()
        first = sample_success_record()
        first["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 脚本统计用户调用次数"}]
        second = sample_success_record()
        second["request_body"]["messages"] = [{"role": "user", "content": "请分析为什么用户调用次数下降"}]
        records = []
        for index, raw in enumerate([first, second]):
            canonical, reject = pipeline.build_canonical_sample(
                "2026-07-15",
                {"request_id": "request-%d" % index, "file_path": "2026-07-15/u/s/%03d.json" % index},
                raw,
            )
            self.assertIsNone(reject)
            records.append(pipeline.annotate_task_and_quality(canonical, config))
        pipeline.apply_dedupe_annotations_to_records(records, config)
        self.assertFalse(any("near_duplicate_content" in item["quality"]["reject_reasons"] for item in records))
```

- [ ] **步骤 6：运行不同 bucket 测试验证通过**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_similar_prompt_in_different_route_bucket_is_not_near_duplicate -v
```

预期：PASS。

- [ ] **步骤 7：编写 debug control repeat 测试**

在 `SelectionDedupeTest` 加：

```python
    def test_repeated_control_turns_trigger_debug_noise_repeat(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            for index in range(3):
                raw = sample_success_record()
                raw["request_id"] = "request-%d" % index
                raw["timestamp"] = "2026-07-15T00:0%d:00+08:00" % index
                raw["request_body"]["messages"] = [{"role": "user", "content": "继续"}]
                raw["response_body"]["choices"][0]["message"]["content"] = "继续处理。"
                write_json(day / "tenant" / "user" / "session" / ("%03d.json" % index), raw)
            write_index(day, [
                {"request_id": "request-%d" % index, "file_path": "2026-07-15/tenant/user/session/%03d.json" % (index, index)}
                for index in range(3)
            ])

            pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                selected_min_score=0.1,
                router_min_score=0.1,
            )

            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertTrue(any("debug_noise_repeat" in row["reject_reasons"] for row in quality))
            self.assertTrue(any("debug_noise" in row["quality"]["risk_labels"] for row in quality))
```

- [ ] **步骤 8：实现 session key 和 debug repeat**

新增 helpers：

```python
def dedupe_session_key(canonical):
    source = canonical.get("source", {})
    return "%s:%s:%s" % (
        source.get("tenant_hash") or "unknown",
        source.get("user_hash") or "unknown",
        source.get("session_hash") or "missing",
    )


def is_debug_control_text(text):
    normalized = normalize_for_dedupe(text)
    return normalized in DEBUG_CONTROL_TEXTS or normalized in CONTINUATION_TERMS
```

在 `apply_dedupe_annotation` 中 near duplicate 后加入：

```python
    if config.get("enable_debug_noise_filter", True):
        session_key = dedupe_session_key(canonical)
        control_key = "%s:%s" % (session_key, text)
        if is_debug_control_text(text):
            state["session_control_counts"][control_key] = state["session_control_counts"].get(control_key, 0) + 1
            if state["session_control_counts"][control_key] > config.get("max_debug_control_repeats_per_session", 2):
                quality["dedupe"]["decision"] = "rejected"
                quality["dedupe"]["matched_reason"] = "debug_noise_repeat"
                mark_dedupe_reject(canonical, state, "debug_noise_repeat", "debug_noise")
                return canonical
```

- [ ] **步骤 9：运行 debug repeat 测试验证通过**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_repeated_control_turns_trigger_debug_noise_repeat -v
```

预期：PASS。

- [ ] **步骤 10：编写 debug burst 测试**

在 `SelectionDedupeTest` 加：

```python
    def test_same_session_task_burst_triggers_debug_burst(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            for index in range(4):
                raw = sample_success_record()
                raw["request_id"] = "request-%d" % index
                raw["timestamp"] = "2026-07-15T00:0%d:00+08:00" % index
                raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 代码打印 hello"}]
                raw["response_body"]["choices"][0]["message"]["content"] = "print('hello %d')" % index
                write_json(day / "tenant" / "user" / "session" / ("%03d.json" % index), raw)
            write_index(day, [
                {"request_id": "request-%d" % index, "file_path": "2026-07-15/tenant/user/session/%03d.json" % (index, index)}
                for index in range(4)
            ])

            pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                max_debug_task_burst_per_session=2,
                near_duplicate_jaccard=1.1,
            )

            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertTrue(any("debug_burst" in row["reject_reasons"] for row in quality))
```

- [ ] **步骤 11：实现 debug burst**

在 `apply_dedupe_annotation` 中 debug repeat 后加入：

```python
        task_key = "%s:%s" % (session_key, canonical.get("task", {}).get("task_fingerprint_internal") or "unknown")
        event_time = canonical.get("source", {}).get("event_time_ms")
        times = state["session_task_times"].setdefault(task_key, [])
        if event_time is not None:
            window_ms = int(config.get("debug_burst_window_minutes", 20)) * 60 * 1000
            times[:] = [item for item in times if event_time - item <= window_ms]
            times.append(event_time)
            if len(times) > config.get("max_debug_task_burst_per_session", 8):
                quality["dedupe"]["decision"] = "rejected"
                quality["dedupe"]["matched_reason"] = "debug_burst"
                mark_dedupe_reject(canonical, state, "debug_burst", "debug_burst")
                return canonical
```

- [ ] **步骤 12：运行任务 3 测试**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_near_duplicate_prompt_in_same_bucket_is_filtered tests.test_audit_training_pipeline.SelectionDedupeTest.test_similar_prompt_in_different_route_bucket_is_not_near_duplicate tests.test_audit_training_pipeline.SelectionDedupeTest.test_repeated_control_turns_trigger_debug_noise_repeat tests.test_audit_training_pipeline.SelectionDedupeTest.test_same_session_task_burst_triggers_debug_burst -v
```

预期：4 个测试 PASS。

- [ ] **步骤 13：Commit**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "feat: suppress near duplicate audit noise"
```

### 任务 4：Spool、report、manifest 和 CLI 配置

**文件：**
- 修改：`scripts/audit_training_pipeline.py:2108-2155`
- 修改：`scripts/audit_training_pipeline.py:2294-2325`
- 修改：`scripts/audit_training_pipeline.py:2533-2910`
- 测试：`tests/test_audit_training_pipeline.py`

- [ ] **步骤 1：编写 report 聚合测试**

在 `SelectionDedupeTest` 加：

```python
    def test_quality_stats_include_risk_labels_and_dedupe_summary(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            for index in range(2):
                raw = sample_success_record()
                raw["request_id"] = "request-%d" % index
                raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 代码打印 hello"}]
                raw["response_body"]["choices"][0]["message"]["content"] = "print('hello')"
                write_json(day / "u" / "s" / ("%03d.json" % index), raw)
            write_index(day, [
                {"request_id": "request-0", "file_path": "2026-07-15/u/s/000.json"},
                {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            ])

            pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

            stats = json.loads((output_root / "reports" / "2026-07-15.quality_stats.json").read_text(encoding="utf-8"))
            self.assertIn("risk_labels", stats)
            self.assertIn("dedupe", stats)
            self.assertEqual(stats["dedupe"]["duplicate_content"], 1)
            self.assertGreaterEqual(stats["risk_labels"].get("duplicate", 0), 1)
```

- [ ] **步骤 2：运行 report 测试验证失败**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_quality_stats_include_risk_labels_and_dedupe_summary -v
```

预期：FAIL，`risk_labels` 或 `dedupe` 缺失。

- [ ] **步骤 3：扩展 report state**

修改 `init_selection_report_state`：

```python
        "risk_counts": {},
        "dedupe_counts": {},
```

修改 `update_selection_report_state`：

```python
    for label in quality.get("risk_labels") or []:
        add_count(state["risk_counts"], label)
    for reason in quality.get("reject_reasons") or []:
        if reason in DEDUPE_REJECT_REASONS:
            add_count(state["dedupe_counts"], reason)
    if "dedupe_state_saturated" in (quality.get("risk_labels") or []):
        add_count(state["dedupe_counts"], "state_saturated")
```

修改 `quality_stats_from_state`：

```python
        "risk_labels": k_suppressed_counts(state.get("risk_counts", {}), k_threshold),
        "dedupe": k_suppressed_counts(state.get("dedupe_counts", {}), k_threshold),
```

- [ ] **步骤 4：运行 report 测试验证通过**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_quality_stats_include_risk_labels_and_dedupe_summary -v
```

预期：PASS。


- [ ] **Step 5: Add safe quality dedupe metadata test**

Add this test to `SelectionDedupeTest`:

```python
    def test_quality_output_includes_safe_dedupe_metadata_without_raw_text(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            raw = sample_success_record()
            raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 代码打印 secret text"}]
            write_json(day / "u" / "s" / "001.json", raw)
            write_index(day, [{"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}])

            pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")[0]
            dumped = json.dumps(quality, ensure_ascii=False)
            self.assertIn("dedupe", quality["quality"])
            self.assertIn("prompt_hash", quality["quality"]["dedupe"])
            self.assertNotIn("secret text", dumped)
            self.assertNotIn("request-1", dumped)
```

- [ ] **Step 6: Expose safe dedupe block in quality diagnostics**

Modify `quality_export_record` and add the dedupe block inside the nested `quality` object:

```python
            "dedupe": copy.deepcopy(quality.get("dedupe") or {}),
```

Do not add this block to selected export metadata.

- [ ] **Step 7: Run quality dedupe metadata test**

Run:

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_quality_output_includes_safe_dedupe_metadata_without_raw_text -v
```

Expected: PASS.

- [ ] **Step 8: Add spool compatibility test**

在 `SelectionDedupeTest` 加：

```python
    def test_spool_mode_applies_dedupe_before_quality_and_selected_outputs(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            for index in range(2):
                raw = sample_success_record()
                raw["request_id"] = "request-%d" % index
                raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 代码打印 hello"}]
                raw["response_body"]["choices"][0]["message"]["content"] = "print('hello')"
                write_json(day / "u" / "s" / ("%03d.json" % index), raw)
            write_index(day, [
                {"request_id": "request-0", "file_path": "2026-07-15/u/s/000.json"},
                {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            ])

            result = pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                selection_mode="spool",
            )

            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            selected = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            self.assertEqual(result["selection"]["mode_used"], "spool")
            self.assertEqual(len(selected), 1)
            self.assertTrue(any("duplicate_content" in row["reject_reasons"] for row in quality))
```

- [ ] **Step 9: Wire spool order**

修改 `process_spooled_selection_records`，确保 dedupe 先于 report 和 selected：

```python
def process_spooled_selection_records(spool_path, config, date, handles=None):
    report_state = init_selection_report_state()
    selected_state = init_selected_export_state()
    dedupe_state = init_dedupe_state(config)
    current_episode = []
    ...
    for canonical in iter_jsonl_records(spool_path):
        apply_dedupe_annotation(canonical, config, dedupe_state)
        refresh_selection_use_for(canonical, config)
        update_selection_report_state(report_state, canonical)
        consider_selected_record(canonical, config, selected_state)
        ...
```

这个顺序有意修正设计文档中较宽泛的 spool 行为描述，保证 `quality_stats` 能看到 dedupe reject。

- [ ] **Step 10: Run spool test**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_spool_mode_applies_dedupe_before_quality_and_selected_outputs -v
```

预期：PASS。

- [ ] **Step 11: Add manifest and CLI tests**

扩展 `SelectionPipelineTest.test_parse_args_accepts_selection_controls_and_rejects_conflicts` 的 argv，加入：

```python
            "--disable-dedupe",
            "--disable-near-duplicate-dedupe",
            "--disable-debug-noise-filter",
            "--near-duplicate-simhash-hamming", "5",
            "--near-duplicate-jaccard", "0.9",
            "--max-debug-control-repeats-per-session", "3",
            "--max-debug-task-burst-per-session", "9",
```

并断言：

```python
        self.assertTrue(args.disable_dedupe)
        self.assertTrue(args.disable_near_duplicate_dedupe)
        self.assertTrue(args.disable_debug_noise_filter)
        self.assertEqual(args.near_duplicate_simhash_hamming, 5)
        self.assertEqual(args.max_debug_task_burst_per_session, 9)
```

在 `SelectionDedupeTest` 加：

```python
    def test_selection_manifest_records_dedupe_config(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            write_json(day / "u" / "s" / "001.json", sample_success_record())
            write_index(day, [{"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}])

            result = pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                near_duplicate_simhash_hamming=5,
            )

            self.assertTrue(result["selection"]["dedupe_enabled"])
            self.assertEqual(result["selection"]["dedupe_config"]["near_duplicate_simhash_hamming"], 5)
            manifest = json.loads((output_root / "reports" / "2026-07-15.selection_manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["selection"]["dedupe_enabled"])
```

- [ ] **Step 12: Implement CLI and manifest config**

给 `process_date` 增加参数：

```python
    disable_dedupe=False,
    disable_near_duplicate_dedupe=False,
    disable_debug_noise_filter=False,
    near_duplicate_simhash_hamming=4,
    near_duplicate_jaccard=0.88,
    max_debug_control_repeats_per_session=2,
    max_debug_task_burst_per_session=8,
```

传入 `default_selection_config`：

```python
        enable_dedupe=not disable_dedupe,
        enable_near_duplicate_dedupe=not disable_near_duplicate_dedupe,
        enable_debug_noise_filter=not disable_debug_noise_filter,
        near_duplicate_simhash_hamming=near_duplicate_simhash_hamming,
        near_duplicate_jaccard=near_duplicate_jaccard,
        max_debug_control_repeats_per_session=max_debug_control_repeats_per_session,
        max_debug_task_burst_per_session=max_debug_task_burst_per_session,
```

扩展 manifest `selection`：

```python
                "dedupe_enabled": bool(config.get("enable_dedupe", True)),
                "dedupe_config": {
                    "enable_near_duplicate_dedupe": bool(config.get("enable_near_duplicate_dedupe", True)),
                    "enable_debug_noise_filter": bool(config.get("enable_debug_noise_filter", True)),
                    "near_duplicate_simhash_hamming": config.get("near_duplicate_simhash_hamming"),
                    "near_duplicate_jaccard": config.get("near_duplicate_jaccard"),
                    "max_debug_control_repeats_per_session": config.get("max_debug_control_repeats_per_session"),
                    "max_debug_task_burst_per_session": config.get("max_debug_task_burst_per_session"),
                },
```

给 `parse_args` 加参数：

```python
    parser.add_argument("--disable-dedupe", action="store_true")
    parser.add_argument("--disable-near-duplicate-dedupe", action="store_true")
    parser.add_argument("--disable-debug-noise-filter", action="store_true")
    parser.add_argument("--near-duplicate-simhash-hamming", type=non_negative_int, default=4)
    parser.add_argument("--near-duplicate-jaccard", type=positive_float, default=0.88)
    parser.add_argument("--max-debug-control-repeats-per-session", type=non_negative_int, default=2)
    parser.add_argument("--max-debug-task-burst-per-session", type=non_negative_int, default=8)
```

在 `main` 的 `process_date` 调用传入对应 args。

- [ ] **Step 13: Run task 4 tests**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionPipelineTest.test_parse_args_accepts_selection_controls_and_rejects_conflicts tests.test_audit_training_pipeline.SelectionDedupeTest.test_quality_stats_include_risk_labels_and_dedupe_summary tests.test_audit_training_pipeline.SelectionDedupeTest.test_spool_mode_applies_dedupe_before_quality_and_selected_outputs tests.test_audit_training_pipeline.SelectionDedupeTest.test_selection_manifest_records_dedupe_config -v
```

预期：4 个测试 PASS。

- [ ] **Step 14: Commit**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "feat: report audit dedupe decisions"
```

### 任务 5：文档、禁用行为、全量验证

**文件：**
- 修改：`audit_training/README.md`
- 修改：`tests/test_audit_training_pipeline.py`
- 可能修改：`scripts/audit_training_pipeline.py`

- [ ] **步骤 1：编写 disable dedupe 行为测试**

在 `SelectionDedupeTest` 加：

```python
    def test_disable_dedupe_keeps_new_dedupe_rejects_off_but_selected_seen_guard_remains(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            for index in range(2):
                raw = sample_success_record()
                raw["request_id"] = "request-%d" % index
                raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 代码打印 hello"}]
                raw["response_body"]["choices"][0]["message"]["content"] = "print('hello')"
                write_json(day / "u" / "s" / ("%03d.json" % index), raw)
            write_index(day, [
                {"request_id": "request-0", "file_path": "2026-07-15/u/s/000.json"},
                {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            ])

            pipeline.process_date(str(input_root), str(output_root), "2026-07-15", disable_dedupe=True)

            selected = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertEqual(len(selected), 1)
            self.assertFalse(any("duplicate_content" in row["reject_reasons"] for row in quality))
```

- [ ] **步骤 2：运行 disable dedupe 测试**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.SelectionDedupeTest.test_disable_dedupe_keeps_new_dedupe_rejects_off_but_selected_seen_guard_remains -v
```

预期：PASS。如果失败，调整 `apply_dedupe_annotation` 让 `enable_dedupe=False` 只写安全 dedupe block，不添加新 reject。

- [ ] **步骤 3：更新 README 测试**

扩展 `PipelineImportTest.test_readme_documents_selected_outputs_and_explicit_labelers` token 列表，加入：

```python
            "--disable-dedupe",
            "--disable-near-duplicate-dedupe",
            "--disable-debug-noise-filter",
            "dedupe",
            "debug noise",
```

- [ ] **步骤 4：运行 README 测试验证失败**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.PipelineImportTest.test_readme_documents_selected_outputs_and_explicit_labelers -v
```

预期：FAIL，README 缺少新 token。

- [ ] **步骤 5：更新 `audit_training/README.md`**

在 "Useful output switches" 后新增：

```markdown
Dedupe and debug-noise controls:

```text
--disable-dedupe                    Disable the new quality-layer duplicate and debug-noise rejects.
--disable-near-duplicate-dedupe     Keep exact/normalized dedupe but skip SimHash near-duplicate filtering.
--disable-debug-noise-filter        Keep duplicate filtering but skip repeated control-turn and burst filtering.
```

Selected exports still keep a final exact `seen` guard even when `--disable-dedupe`
is used, so repeated selected records are not written twice.
```

在 reports 段落补充：

```markdown
`quality_stats` includes aggregate `risk_labels` and `dedupe` counts for duplicate
content, normalized duplicates, near duplicates, debug noise, debug bursts, and
state saturation. These reports contain only counts and hashes, not raw prompts.
```

- [ ] **步骤 6：运行 README 测试验证通过**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_audit_training_pipeline.PipelineImportTest.test_readme_documents_selected_outputs_and_explicit_labelers -v
```

预期：PASS。

- [ ] **步骤 7：运行完整测试**

运行：

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

预期：全部测试 PASS。当前基线是 135 个测试；新增测试后数量会增加，失败数必须为 0。

- [ ] **步骤 8：运行 whitespace 检查**

运行：

```bash
git diff --check
```

预期：无输出，exit 0。

- [ ] **步骤 9：检查敏感输出边界**

运行：

```bash
rg -n "request_id|tenant_hash|user_hash|session_hash|file_path_hash|content_hash|task_fingerprint_internal" audit_training/README.md scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
```

预期：这些 token 只出现在已有 forbidden-key 检查、内部 canonical/quality 逻辑、README 安全说明或测试断言中；不要把它们加入 selected record metadata。

- [ ] **步骤 10：Commit**

```bash
git add audit_training/README.md scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "docs: document audit dedupe controls"
```

## 最终验收

- [ ] 所有任务 commit 均在当前 worktree 分支上。
- [ ] `env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v` 通过。
- [ ] `git diff --check` 通过。
- [ ] `git status --short --branch` 只显示预期分支状态，没有未暂存改动。
- [ ] `selected/*` 不包含新的内部 dedupe hash 字段。
- [ ] `quality/*` 可以解释 dedupe/noise reject，但不包含 raw prompt、raw response、request ID、tenant/user/session hash 或 file path。
- [ ] README 明确说明 raw/canonical/legacy 保留，训练默认使用 `selected/*`。
