# Audit Training Data Pipeline 实现计划

> **面向 AI 代理的工作者：** 必需子技能：使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务实现此计划。步骤使用复选框（`- [ ]`）语法来跟踪进度。

**目标：** 构建一个可定时运行的 audit 日志清洗脚本，把 `/isos_data_share/audit/YYYY-MM-DD/` 转换为脱敏、可审计、可复跑的 canonical、SFT、tool-use SFT、router classification 和质量报告数据。

**架构：** 采用 canonical-first 管道：原始 audit 明细先被流式读取、脱敏、标准化为 canonical JSONL，再由独立导出函数生成各训练任务数据。脚本只依赖 Python 标准库，默认输出到 `/ai_paas_jf/sunlg/data/audit_training`，在当前 `data` 仓库内的相对路径为 `audit_training/`。

**技术栈：** Python 3 标准库（`argparse`、`json`、`hashlib`、`datetime`、`re`、`tempfile`、`shutil`、`urllib.request`、`unittest`），GitHub remote `git@github.com:guangzai1995/data-process.git`。

---

## 文件结构

- 创建：`scripts/audit_training_pipeline.py`
  - 单文件实现 CLI、读取、脱敏、canonical 构建、导出、可选模型标注、原子写入。第一版保持单文件，便于在当前数据工作区直接运行；函数边界按职责拆清，后续可无痛拆包。
- 创建：`tests/test_audit_training_pipeline.py`
  - 使用 `unittest` 覆盖脱敏、hash、索引读取、明细加载、canonical 构建、导出器、模型标注解析、CLI 管道。
- 创建：`audit_training/README.md`
  - 记录输出目录结构、运行命令、环境变量、默认忽略策略。
- 修改：`.gitignore`
  - 当前已默认忽略大数据和生成物；如实现中新增轻量配置或 fixture 目录，确保它们可被 Git 跟踪。

## 任务 1：测试骨架与最小模块

**文件：**
- 创建：`scripts/audit_training_pipeline.py`
- 创建：`tests/test_audit_training_pipeline.py`

- [ ] **步骤 1：编写失败的导入测试**

在 `tests/test_audit_training_pipeline.py` 写入：

```python
import importlib.util
import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "audit_training_pipeline.py"


def load_pipeline_module():
    spec = importlib.util.spec_from_file_location("audit_training_pipeline", str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PipelineImportTest(unittest.TestCase):
    def test_pipeline_version_is_declared(self):
        pipeline = load_pipeline_module()
        self.assertEqual(pipeline.PIPELINE_VERSION, "2026.07.16")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **步骤 2：运行测试验证失败**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline -v
```

预期：FAIL，报错包含 `No such file or directory` 或 `FileNotFoundError`，因为 `scripts/audit_training_pipeline.py` 尚未创建。

- [ ] **步骤 3：创建最小模块**

创建 `scripts/audit_training_pipeline.py`：

```python
#!/usr/bin/env python3
"""Clean audit logs into training-ready datasets."""

PIPELINE_VERSION = "2026.07.16"
DEFAULT_INPUT_ROOT = "/isos_data_share/audit"
DEFAULT_OUTPUT_ROOT = "audit_training"
```

- [ ] **步骤 4：运行测试验证通过**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline -v
```

预期：PASS，`test_pipeline_version_is_declared` 通过。

- [ ] **步骤 5：Commit**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "test: add audit pipeline test scaffold"
```

## 任务 2：脱敏与标识 hash

**文件：**
- 修改：`scripts/audit_training_pipeline.py`
- 修改：`tests/test_audit_training_pipeline.py`

- [ ] **步骤 1：编写脱敏与 hash 测试**

追加到 `tests/test_audit_training_pipeline.py`：

```python
class RedactionTest(unittest.TestCase):
    def test_redact_text_replaces_sensitive_values_with_stable_tokens(self):
        pipeline = load_pipeline_module()
        text = (
            "联系 13800138000 或 user@example.com，身份证 11010519491231002X，"
            "Bearer sk-abcdefghijklmnopqrstuvwxyz1234567890，再次联系 13800138000"
        )
        redacted, stats = pipeline.redact_text(text)
        self.assertNotIn("13800138000", redacted)
        self.assertNotIn("user@example.com", redacted)
        self.assertNotIn("11010519491231002X", redacted)
        self.assertIn("<PHONE_1>", redacted)
        self.assertEqual(redacted.count("<PHONE_1>"), 2)
        self.assertIn("<EMAIL_1>", redacted)
        self.assertIn("<CN_ID_1>", redacted)
        self.assertGreaterEqual(stats["phone"], 1)
        self.assertGreaterEqual(stats["email"], 1)
        self.assertGreaterEqual(stats["cn_id"], 1)
        self.assertGreaterEqual(stats["secret"], 1)

    def test_hash_identifier_is_deterministic_and_not_plaintext(self):
        pipeline = load_pipeline_module()
        first = pipeline.hash_identifier("tenant-123")
        second = pipeline.hash_identifier("tenant-123")
        other = pipeline.hash_identifier("tenant-456")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertNotIn("tenant-123", first)
        self.assertEqual(len(first), 16)
```

- [ ] **步骤 2：运行测试验证失败**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.RedactionTest -v
```

预期：FAIL，报错包含 `AttributeError: module 'audit_training_pipeline' has no attribute 'redact_text'`。

- [ ] **步骤 3：实现最小脱敏函数**

在 `scripts/audit_training_pipeline.py` 追加：

```python
import hashlib
import re


REDACTION_PATTERNS = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone", re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")),
    ("cn_id", re.compile(r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)")),
    ("bank_card", re.compile(r"(?<!\d)(?:\d[ -]?){16,19}(?!\d)")),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("secret", re.compile(r"(?i)\b(?:bearer\s+)?(?:sk-|ak-|api[_-]?key[:=]?|secret[:=]?)[A-Za-z0-9_\-]{16,}\b")),
]


def hash_identifier(value):
    if value is None or value == "":
        return ""
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    return digest[:16]


def redact_text(text):
    if text is None:
        return "", {}
    result = str(text)
    stats = {}
    replacements = {}
    for name, pattern in REDACTION_PATTERNS:
        stats.setdefault(name, 0)

        def replace(match):
            raw = match.group(0)
            key = (name, raw)
            if key not in replacements:
                stats[name] += 1
                replacements[key] = "<%s_%d>" % (name.upper(), stats[name])
            return replacements[key]

        result = pattern.sub(replace, result)
    return result, stats
```

- [ ] **步骤 4：运行测试验证通过**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.RedactionTest -v
```

预期：PASS。

- [ ] **步骤 5：Commit**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "feat: add audit text redaction"
```

## 任务 3：索引读取与明细加载

**文件：**
- 修改：`scripts/audit_training_pipeline.py`
- 修改：`tests/test_audit_training_pipeline.py`

- [ ] **步骤 1：编写索引与明细读取测试**

追加到 `tests/test_audit_training_pipeline.py`：

```python
import json
import tempfile


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


class AuditReadTest(unittest.TestCase):
    def test_iter_index_records_skips_blank_and_bad_lines(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            day = root / "2026-07-15"
            day.mkdir(parents=True)
            index = day / "_request_index.jsonl"
            index.write_text(
                "\n"
                "{\"request_id\":\"r1\",\"file_path\":\"2026-07-15/u/s/001.json\"}\n"
                "{bad json}\n"
                "{\"request_id\":\"r2\",\"file_path\":\"2026-07-15/u/s/002.json\"}\n",
                encoding="utf-8",
            )
            events = list(pipeline.iter_index_records(root, "2026-07-15"))
            records = [record for record, error in events if record is not None]
            errors = [error for record, error in events if error is not None]
            self.assertEqual([record["request_id"] for record in records], ["r1", "r2"])
            self.assertEqual(errors[0]["reason"], "bad_index_json")

    def test_load_audit_record_returns_error_for_missing_file(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            record = {"request_id": "missing", "file_path": "2026-07-15/u/s/nope.json"}
            loaded, error = pipeline.load_audit_record(root, record)
            self.assertIsNone(loaded)
            self.assertEqual(error["reason"], "missing_detail_file")

    def test_load_audit_record_loads_valid_json(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            detail_path = root / "2026-07-15" / "u" / "s" / "001.json"
            write_json(detail_path, {"request_id": "r1", "status": "success"})
            loaded, error = pipeline.load_audit_record(
                root,
                {"request_id": "r1", "file_path": "2026-07-15/u/s/001.json"},
            )
            self.assertIsNone(error)
            self.assertEqual(loaded["request_id"], "r1")
```

- [ ] **步骤 2：运行测试验证失败**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.AuditReadTest -v
```

预期：FAIL，报错包含 `AttributeError`，缺少 `iter_index_records` 或 `load_audit_record`。

- [ ] **步骤 3：实现流式索引读取和明细加载**

在 `scripts/audit_training_pipeline.py` 追加：

```python
import json
import pathlib


def iter_index_records(input_root, date):
    root = pathlib.Path(input_root)
    index_path = root / date / "_request_index.jsonl"
    with index_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except ValueError:
                yield None, {"line": line_number, "reason": "bad_index_json"}
                continue
            if not record.get("request_id") or not record.get("file_path"):
                yield None, {"line": line_number, "reason": "bad_index_record"}
                continue
            yield record, None


def load_audit_record(input_root, index_record):
    root = pathlib.Path(input_root)
    detail_path = root / index_record["file_path"]
    if not detail_path.exists():
        return None, {
            "request_id": index_record.get("request_id"),
            "file_path": index_record.get("file_path"),
            "reason": "missing_detail_file",
        }
    try:
        with detail_path.open("r", encoding="utf-8") as handle:
            return json.load(handle), None
    except ValueError:
        return None, {
            "request_id": index_record.get("request_id"),
            "file_path": index_record.get("file_path"),
            "reason": "bad_detail_json",
        }
```

- [ ] **步骤 4：运行测试验证通过**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.AuditReadTest -v
```

预期：PASS。

- [ ] **步骤 5：Commit**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "feat: read audit index and detail records"
```

## 任务 4：Canonical 样本构建与质量规则

**文件：**
- 修改：`scripts/audit_training_pipeline.py`
- 修改：`tests/test_audit_training_pipeline.py`

- [ ] **步骤 1：编写 canonical 构建测试**

追加到 `tests/test_audit_training_pipeline.py`：

```python
def sample_success_record():
    return {
        "timestamp": "2026-07-15T00:00:00+08:00",
        "user_id": "user-1",
        "tenant_id": "tenant-1",
        "api_key_id": "key-1",
        "session_id": "session-1",
        "client_ip": "10.1.2.3",
        "request_id": "request-1",
        "request_path": "/api/v1/openai/v1/chat/completions",
        "model": "glm-5.2",
        "client_type": "opencode",
        "status": "success",
        "request_body": {
            "model": "glm-5.2",
            "stream": False,
            "messages": [
                {"role": "user", "content": "请写一段 Python 代码，联系 13800138000"}
            ],
            "temperature": 0.3,
        },
        "response_body": {
            "choices": [
                {
                    "message": {"role": "assistant", "content": "可以使用 print('hello')"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        },
    }


class CanonicalBuildTest(unittest.TestCase):
    def test_build_canonical_sample_accepts_success_record(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        self.assertEqual(canonical["source"]["date"], "2026-07-15")
        self.assertEqual(canonical["routing"]["weak_model_label"], "glm-5.2")
        self.assertEqual(canonical["quality"]["status"], "accepted")
        self.assertIn("<PHONE_1>", canonical["request"]["messages"][0]["content"])
        self.assertNotIn("tenant-1", json.dumps(canonical, ensure_ascii=False))
        self.assertIn("router", canonical["quality"]["task_types"])

    def test_build_canonical_sample_rejects_failed_record(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["status"] = "failed"
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(canonical)
        self.assertEqual(reject["reason"], "status_not_success")

    def test_build_canonical_sample_rejects_empty_assistant_response(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["response_body"]["choices"][0]["message"]["content"] = ""
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(canonical)
        self.assertEqual(reject["reason"], "empty_assistant_response")
```

- [ ] **步骤 2：运行测试验证失败**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.CanonicalBuildTest -v
```

预期：FAIL，报错包含 `AttributeError: module 'audit_training_pipeline' has no attribute 'build_canonical_sample'`。

- [ ] **步骤 3：实现 canonical 样本构建**

在 `scripts/audit_training_pipeline.py` 中添加这些函数：

```python
def stable_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_hash(value):
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def redact_value_tree(value):
    if isinstance(value, str):
        redacted, stats = redact_text(value)
        return redacted, stats
    if isinstance(value, list):
        redacted_items = []
        merged = {}
        for item in value:
            redacted, stats = redact_value_tree(item)
            redacted_items.append(redacted)
            for key, count in stats.items():
                merged[key] = merged.get(key, 0) + count
        return redacted_items, merged
    if isinstance(value, dict):
        redacted_dict = {}
        merged = {}
        for key, item in value.items():
            redacted, stats = redact_value_tree(item)
            redacted_dict[key] = redacted
            for stat_key, count in stats.items():
                merged[stat_key] = merged.get(stat_key, 0) + count
        return redacted_dict, merged
    return value, {}


def first_response_choice(raw_record):
    choices = (raw_record.get("response_body") or {}).get("choices") or []
    if not choices:
        return None
    return choices[0]


def assistant_text_from_choice(choice):
    message = choice.get("message") or {}
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    return ""


def build_canonical_sample(date, index_record, raw_record, max_prompt_chars=200000, max_response_chars=100000):
    if raw_record.get("status") != "success":
        return None, reject_record(date, index_record, "status_not_success")
    request_body = raw_record.get("request_body") or {}
    messages = request_body.get("messages")
    if not isinstance(messages, list) or not messages:
        return None, reject_record(date, index_record, "missing_messages")
    choice = first_response_choice(raw_record)
    if choice is None:
        return None, reject_record(date, index_record, "missing_choices")
    response_text = assistant_text_from_choice(choice)
    if not response_text and not ((choice.get("message") or {}).get("tool_calls")):
        return None, reject_record(date, index_record, "empty_assistant_response")
    if len(stable_json(messages)) > max_prompt_chars:
        return None, reject_record(date, index_record, "prompt_too_long")
    if len(response_text) > max_response_chars:
        return None, reject_record(date, index_record, "response_too_long")

    redacted_messages, message_stats = redact_value_tree(messages)
    redacted_tools, tool_stats = redact_value_tree(request_body.get("tools") or [])
    redacted_response, response_stats = redact_value_tree(choice.get("message") or {})
    stats = merge_counts(message_stats, tool_stats, response_stats)
    request_payload_for_hash = {
        "date": date,
        "request_id": raw_record.get("request_id") or index_record.get("request_id"),
        "messages": redacted_messages,
    }
    sample_id = hashlib.sha256(stable_json(request_payload_for_hash).encode("utf-8")).hexdigest()
    finish_reason = choice.get("finish_reason")
    task_types = ["router"]
    if redacted_tools or redacted_response.get("tool_calls"):
        task_types.append("tool_use_sft")
    elif finish_reason != "length":
        task_types.append("sft")

    canonical = {
        "sample_id": sample_id,
        "source": {
            "date": date,
            "request_id": raw_record.get("request_id") or index_record.get("request_id"),
            "file_path": index_record.get("file_path"),
            "tenant_hash": hash_identifier(raw_record.get("tenant_id")),
            "user_hash": hash_identifier(raw_record.get("user_id")),
            "session_hash": hash_identifier(raw_record.get("session_id")),
        },
        "request": {
            "model": raw_record.get("model") or request_body.get("model"),
            "request_path": raw_record.get("request_path"),
            "messages": redacted_messages,
            "tools": redacted_tools,
            "tool_choice": request_body.get("tool_choice"),
            "params": build_request_params(request_body, raw_record),
        },
        "response": {
            "message": redacted_response,
            "finish_reason": finish_reason,
            "usage": (raw_record.get("response_body") or {}).get("usage") or {},
        },
        "routing": {
            "weak_model_label": raw_record.get("model") or request_body.get("model"),
            "weak_expert_label": choice.get("routed_experts"),
            "rule_label": None,
            "model_label": None,
            "label_confidence": "weak",
        },
        "quality": {
            "status": "accepted",
            "task_types": task_types,
            "reject_reasons": [],
            "pii_redacted": bool(sum(stats.values())),
            "redaction_stats": stats,
            "content_hash": content_hash({"messages": redacted_messages, "response": redacted_response}),
        },
    }
    return canonical, None
```

同时添加配套小函数：

```python
def merge_counts(*dicts):
    merged = {}
    for counts in dicts:
        for key, value in counts.items():
            merged[key] = merged.get(key, 0) + value
    return merged


def reject_record(date, index_record, reason):
    return {
        "date": date,
        "request_id": index_record.get("request_id"),
        "file_path": index_record.get("file_path"),
        "reason": reason,
    }


def build_request_params(request_body, raw_record):
    excluded = set(["messages", "tools"])
    params = {key: value for key, value in request_body.items() if key not in excluded}
    params["client_type"] = raw_record.get("client_type") or ""
    params["adapter_type"] = raw_record.get("adapter_type") or ""
    params["is_stream"] = bool(raw_record.get("is_stream"))
    return params
```

- [ ] **步骤 4：运行测试验证通过**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.CanonicalBuildTest -v
```

预期：PASS。

- [ ] **步骤 5：Commit**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "feat: build canonical audit samples"
```

## 任务 5：路由规则与任务导出器

**文件：**
- 修改：`scripts/audit_training_pipeline.py`
- 修改：`tests/test_audit_training_pipeline.py`

- [ ] **步骤 1：编写导出器测试**

追加到 `tests/test_audit_training_pipeline.py`：

```python
class ExporterTest(unittest.TestCase):
    def test_rule_classifier_detects_tool_code_and_long_context(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        self.assertEqual(pipeline.classify_by_rules(canonical), "code_generation")
        canonical["request"]["tools"] = [{"type": "function", "function": {"name": "search"}}]
        self.assertEqual(pipeline.classify_by_rules(canonical), "tool_agent")
        canonical["request"]["tools"] = []
        canonical["response"]["usage"]["prompt_tokens"] = 90000
        self.assertEqual(pipeline.classify_by_rules(canonical), "long_context")

    def test_export_sft_tool_and_router_records(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        sft = pipeline.export_sft(canonical)
        router = pipeline.export_router(canonical)
        self.assertEqual(sft["sample_id"], canonical["sample_id"])
        self.assertIn("input", sft)
        self.assertIn("output", sft)
        self.assertEqual(router["labels"]["rule_label"], "code_generation")
        self.assertEqual(router["labels"]["final_label"], "code_generation")

    def test_export_tool_use_sft_preserves_tool_calls(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["tools"] = [{"type": "function", "function": {"name": "search"}}]
        raw["response_body"]["choices"][0]["finish_reason"] = "tool_calls"
        raw["response_body"]["choices"][0]["message"] = {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "search", "arguments": "{\"q\":\"hello\"}"},
                }
            ],
        }
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        exported = pipeline.export_tool_use_sft(canonical)
        self.assertEqual(exported["response_message"]["tool_calls"][0]["id"], "call_1")
```

- [ ] **步骤 2：运行测试验证失败**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.ExporterTest -v
```

预期：FAIL，缺少 `classify_by_rules`、`export_sft`、`export_router` 或 `export_tool_use_sft`。

- [ ] **步骤 3：实现规则分类和导出器**

在 `scripts/audit_training_pipeline.py` 追加：

```python
ROUTE_LABELS = set([
    "general_chat",
    "code_generation",
    "tool_agent",
    "long_context",
    "reasoning",
    "domain_qa",
    "unsafe_or_invalid",
    "unknown",
])


def last_user_content(messages):
    for message in reversed(messages):
        if message.get("role") == "user":
            return str(message.get("content") or "")
    return ""


def classify_by_rules(canonical):
    request = canonical["request"]
    usage = canonical["response"].get("usage") or {}
    text = last_user_content(request.get("messages") or [])
    lowered = text.lower()
    if request.get("tools") or canonical["response"]["message"].get("tool_calls"):
        return "tool_agent"
    if usage.get("prompt_tokens", 0) >= 64000 or len(stable_json(request.get("messages") or [])) >= 120000:
        return "long_context"
    if any(token in lowered for token in ["python", "代码", "函数", "bug", "sql", "shell", "脚本"]):
        return "code_generation"
    if any(token in lowered for token in ["推理", "证明", "分析", "为什么", "步骤"]):
        return "reasoning"
    if any(token in lowered for token in ["账单", "订单", "用户资料", "营业", "发票"]):
        return "domain_qa"
    return "general_chat"


def final_route_label(canonical):
    model_label = canonical["routing"].get("model_label")
    if isinstance(model_label, dict) and model_label.get("confidence", 0) >= 0.75:
        label = model_label.get("label")
        if label in ROUTE_LABELS:
            return label, "high"
    rule_label = classify_by_rules(canonical)
    if rule_label in ROUTE_LABELS:
        return rule_label, "medium"
    return "unknown", "low"


def export_sft(canonical):
    message = canonical["response"]["message"]
    content = str(message.get("content") or "").strip()
    return {
        "sample_id": canonical["sample_id"],
        "instruction": "",
        "input": last_user_content(canonical["request"]["messages"]),
        "output": content,
        "messages": canonical["request"]["messages"] + [{"role": "assistant", "content": content}],
        "metadata": {
            "source_date": canonical["source"]["date"],
            "model": canonical["request"].get("model"),
        },
    }


def export_tool_use_sft(canonical):
    return {
        "sample_id": canonical["sample_id"],
        "messages": canonical["request"]["messages"],
        "tools": canonical["request"].get("tools") or [],
        "response_message": canonical["response"]["message"],
        "metadata": {
            "source_date": canonical["source"]["date"],
            "finish_reason": canonical["response"].get("finish_reason"),
            "model": canonical["request"].get("model"),
        },
    }


def export_router(canonical):
    rule_label = classify_by_rules(canonical)
    final_label, confidence = final_route_label(canonical)
    usage = canonical["response"].get("usage") or {}
    messages = canonical["request"].get("messages") or []
    return {
        "sample_id": canonical["sample_id"],
        "input": last_user_content(messages),
        "features": {
            "message_count": len(messages),
            "has_tools": bool(canonical["request"].get("tools") or canonical["response"]["message"].get("tool_calls")),
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "client_type": canonical["request"].get("params", {}).get("client_type", ""),
        },
        "labels": {
            "weak_model_label": canonical["routing"].get("weak_model_label"),
            "rule_label": rule_label,
            "model_label": canonical["routing"].get("model_label"),
            "final_label": final_label,
            "confidence": confidence,
        },
    }
```

- [ ] **步骤 4：运行测试验证通过**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.ExporterTest -v
```

预期：PASS。

- [ ] **步骤 5：Commit**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "feat: export audit training tasks"
```

## 任务 6：可选 OpenAI-compatible 模型标注

**文件：**
- 修改：`scripts/audit_training_pipeline.py`
- 修改：`tests/test_audit_training_pipeline.py`

- [ ] **步骤 1：编写模型标注解析测试**

追加到 `tests/test_audit_training_pipeline.py`：

```python
class LabelModelTest(unittest.TestCase):
    def test_parse_label_response_accepts_controlled_json(self):
        pipeline = load_pipeline_module()
        parsed = pipeline.parse_label_response('{"label":"tool_agent","confidence":0.82,"reason":"uses tools"}')
        self.assertEqual(parsed["label"], "tool_agent")
        self.assertEqual(parsed["confidence"], 0.82)

    def test_parse_label_response_rejects_unknown_label(self):
        pipeline = load_pipeline_module()
        parsed = pipeline.parse_label_response('{"label":"bad_label","confidence":0.99,"reason":"no"}')
        self.assertIsNone(parsed)

    def test_label_config_reads_environment(self):
        pipeline = load_pipeline_module()
        env = {
            "AUDIT_LABEL_BASE_URL": "https://example.test/v1",
            "AUDIT_LABEL_API_KEY": "key",
            "AUDIT_LABEL_MODEL": "label-model",
            "AUDIT_LABEL_TIMEOUT": "12",
            "AUDIT_LABEL_MAX_CONCURRENCY": "3",
        }
        config = pipeline.load_label_config(env)
        self.assertTrue(config["enabled"])
        self.assertEqual(config["timeout"], 12)
        self.assertEqual(config["max_concurrency"], 3)
```

- [ ] **步骤 2：运行测试验证失败**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.LabelModelTest -v
```

预期：FAIL，缺少 `parse_label_response` 或 `load_label_config`。

- [ ] **步骤 3：实现模型标注配置和解析**

在 `scripts/audit_training_pipeline.py` 追加：

```python
import os
import urllib.request


def load_label_config(env=None):
    source = env or os.environ
    base_url = source.get("AUDIT_LABEL_BASE_URL", "").rstrip("/")
    api_key = source.get("AUDIT_LABEL_API_KEY", "")
    model = source.get("AUDIT_LABEL_MODEL", "")
    timeout = int(source.get("AUDIT_LABEL_TIMEOUT", "30"))
    max_concurrency = int(source.get("AUDIT_LABEL_MAX_CONCURRENCY", "1"))
    return {
        "enabled": bool(base_url and api_key and model),
        "base_url": base_url,
        "api_key": api_key,
        "model": model,
        "timeout": timeout,
        "max_concurrency": max(1, max_concurrency),
    }


def parse_label_response(text):
    try:
        payload = json.loads(text)
    except ValueError:
        return None
    label = payload.get("label")
    confidence = payload.get("confidence")
    reason = payload.get("reason", "")
    if label not in ROUTE_LABELS:
        return None
    if not isinstance(confidence, (int, float)):
        return None
    return {"label": label, "confidence": float(confidence), "reason": str(reason)}


def call_label_model(router_record, config):
    if not config.get("enabled"):
        return None, "labeler_disabled"
    prompt = {
        "task": "classify_route",
        "labels": sorted(ROUTE_LABELS),
        "sample": router_record,
        "response_format": {"label": "string", "confidence": "number", "reason": "string"},
    }
    body = json.dumps({
        "model": config["model"],
        "messages": [
            {"role": "system", "content": "Return only JSON for route classification."},
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
        ],
        "temperature": 0,
    }).encode("utf-8")
    request = urllib.request.Request(
        config["base_url"] + "/chat/completions",
        data=body,
        headers={
            "Authorization": "Bearer " + config["api_key"],
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=config["timeout"]) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        return None, "labeler_request_failed:%s" % exc.__class__.__name__
    content = (((payload.get("choices") or [{}])[0].get("message") or {}).get("content") or "")
    parsed = parse_label_response(content)
    if parsed is None:
        return None, "labeler_invalid_response"
    return parsed, None
```

- [ ] **步骤 4：运行测试验证通过**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.LabelModelTest -v
```

预期：PASS。

- [ ] **步骤 5：Commit**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "feat: add optional route labeler"
```

## 任务 7：日期处理、管道编排与原子写入

**文件：**
- 修改：`scripts/audit_training_pipeline.py`
- 修改：`tests/test_audit_training_pipeline.py`

- [ ] **步骤 1：编写端到端小样本管道测试**

追加到 `tests/test_audit_training_pipeline.py`：

```python
class PipelineRunTest(unittest.TestCase):
    def test_process_date_writes_expected_outputs(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            detail = day / "u" / "s" / "001.json"
            write_json(detail, sample_success_record())
            (day / "_request_index.jsonl").write_text(
                json.dumps({"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}) + "\n",
                encoding="utf-8",
            )
            result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15", limit=None, dry_run=False)
            self.assertEqual(result["accepted"], 1)
            self.assertTrue((output_root / "canonical" / "2026-07-15.jsonl").exists())
            self.assertTrue((output_root / "sft" / "2026-07-15.jsonl").exists())
            self.assertTrue((output_root / "router_classification" / "2026-07-15.jsonl").exists())
            self.assertTrue((output_root / "reports" / "2026-07-15.stats.json").exists())
            self.assertTrue((output_root / "manifests" / "2026-07-15.manifest.json").exists())

    def test_process_date_dry_run_does_not_write_final_outputs(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            detail = day / "u" / "s" / "001.json"
            write_json(detail, sample_success_record())
            (day / "_request_index.jsonl").write_text(
                json.dumps({"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}) + "\n",
                encoding="utf-8",
            )
            result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15", limit=1, dry_run=True)
            self.assertEqual(result["accepted"], 1)
            self.assertFalse((output_root / "canonical" / "2026-07-15.jsonl").exists())
```

- [ ] **步骤 2：运行测试验证失败**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.PipelineRunTest -v
```

预期：FAIL，缺少 `process_date`。

- [ ] **步骤 3：实现编排和写入**

在 `scripts/audit_training_pipeline.py` 追加：

```python
import datetime
import shutil
import sys
import tempfile


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def write_json_file(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")


def collect_outputs(date, canonical_records, rejects, label_queue, stats, manifest):
    sft_records = []
    tool_records = []
    router_records = []
    for canonical in canonical_records:
        if "sft" in canonical["quality"]["task_types"]:
            sft_records.append(export_sft(canonical))
        if "tool_use_sft" in canonical["quality"]["task_types"]:
            tool_records.append(export_tool_use_sft(canonical))
        router_record = export_router(canonical)
        router_records.append(router_record)
        if router_record["labels"]["confidence"] == "low":
            label_queue.append({"sample_id": canonical["sample_id"], "reason": "low_confidence_route", "router": router_record})
    return {
        "canonical/%s.jsonl" % date: canonical_records,
        "sft/%s.jsonl" % date: sft_records,
        "tool_use_sft/%s.jsonl" % date: tool_records,
        "router_classification/%s.jsonl" % date: router_records,
        "label_queue/%s.jsonl" % date: label_queue,
        "reports/%s.rejects.jsonl" % date: rejects,
        "reports/%s.stats.json" % date: stats,
        "manifests/%s.manifest.json" % date: manifest,
    }


def write_outputs_atomically(output_root, date, outputs):
    output_root = pathlib.Path(output_root)
    tmp_root = output_root / ".tmp" / date
    if tmp_root.exists():
        shutil.rmtree(str(tmp_root))
    tmp_root.mkdir(parents=True)
    for relative, value in outputs.items():
        target = tmp_root / relative
        if relative.endswith(".jsonl"):
            write_jsonl(target, value)
        else:
            write_json_file(target, value)
    for relative in outputs:
        final = output_root / relative
        final.parent.mkdir(parents=True, exist_ok=True)
        temp_file = tmp_root / relative
        if final.exists():
            final.unlink()
        shutil.move(str(temp_file), str(final))
    shutil.rmtree(str(tmp_root))


def process_date(input_root, output_root, date, limit=None, dry_run=False):
    started_at = datetime.datetime.utcnow().isoformat() + "Z"
    canonical_records = []
    rejects = []
    label_queue = []
    index_record_count = 0
    files_loaded = 0
    for index_record, index_error in iter_index_records(input_root, date):
        if index_error is not None:
            rejects.append(index_error)
            continue
        index_record_count += 1
        if limit is not None and files_loaded >= limit:
            break
        raw, error = load_audit_record(input_root, index_record)
        if error:
            rejects.append(error)
            continue
        files_loaded += 1
        canonical, reject = build_canonical_sample(date, index_record, raw)
        if reject:
            rejects.append(reject)
            continue
        canonical_records.append(canonical)
    finished_at = datetime.datetime.utcnow().isoformat() + "Z"
    stats = build_stats(canonical_records, rejects)
    manifest = {
        "date": date,
        "input_root": str(input_root),
        "output_root": str(output_root),
        "index_records": index_record_count,
        "files_loaded": files_loaded,
        "accepted": len(canonical_records),
        "rejected": len(rejects),
        "pipeline_version": PIPELINE_VERSION,
        "started_at": started_at,
        "finished_at": finished_at,
        "dry_run": bool(dry_run),
    }
    outputs = collect_outputs(date, canonical_records, rejects, label_queue, stats, manifest)
    if not dry_run:
        write_outputs_atomically(output_root, date, outputs)
    return manifest
```

同时添加 stats 函数：

```python
def build_stats(canonical_records, rejects):
    stats = {
        "accepted": len(canonical_records),
        "rejected": len(rejects),
        "models": {},
        "finish_reasons": {},
        "task_types": {},
        "reject_reasons": {},
        "redaction_hits": {},
    }
    for canonical in canonical_records:
        model = canonical["request"].get("model") or "unknown"
        stats["models"][model] = stats["models"].get(model, 0) + 1
        finish_reason = canonical["response"].get("finish_reason") or "unknown"
        stats["finish_reasons"][finish_reason] = stats["finish_reasons"].get(finish_reason, 0) + 1
        for task_type in canonical["quality"].get("task_types", []):
            stats["task_types"][task_type] = stats["task_types"].get(task_type, 0) + 1
        for key, value in canonical["quality"].get("redaction_stats", {}).items():
            stats["redaction_hits"][key] = stats["redaction_hits"].get(key, 0) + value
    for reject in rejects:
        reason = reject.get("reason", "unknown")
        stats["reject_reasons"][reason] = stats["reject_reasons"].get(reason, 0) + 1
    return stats
```

- [ ] **步骤 4：运行测试验证通过**

运行：

```bash
python3 -m unittest tests.test_audit_training_pipeline.PipelineRunTest -v
```

预期：PASS。

- [ ] **步骤 5：Commit**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py
git commit -m "feat: orchestrate audit pipeline outputs"
```

## 任务 8：CLI、README、全量验证与推送

**文件：**
- 修改：`scripts/audit_training_pipeline.py`
- 创建：`audit_training/README.md`

- [ ] **步骤 1：实现 CLI 日期参数**

在 `scripts/audit_training_pipeline.py` 追加：

```python
import argparse


def yesterday_date():
    return (datetime.date.today() - datetime.timedelta(days=1)).isoformat()


def date_range(start_date, end_date):
    start = datetime.datetime.strptime(start_date, "%Y-%m-%d").date()
    end = datetime.datetime.strptime(end_date, "%Y-%m-%d").date()
    current = start
    dates = []
    while current <= end:
        dates.append(current.isoformat())
        current += datetime.timedelta(days=1)
    return dates


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Clean audit logs into training-ready datasets.")
    parser.add_argument("--input-root", default=DEFAULT_INPUT_ROOT)
    parser.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--date")
    parser.add_argument("--start-date")
    parser.add_argument("--end-date")
    parser.add_argument("--yesterday", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def resolve_dates(args):
    if args.yesterday:
        return [yesterday_date()]
    if args.date:
        return [args.date]
    if args.start_date and args.end_date:
        return date_range(args.start_date, args.end_date)
    raise SystemExit("Provide --yesterday, --date, or --start-date with --end-date")


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    results = []
    for date in resolve_dates(args):
        result = process_date(args.input_root, args.output_root, date, limit=args.limit, dry_run=args.dry_run)
        results.append(result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **步骤 2：编写输出 README**

创建 `audit_training/README.md`：

````markdown
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
````

- [ ] **步骤 3：运行完整单元测试**

运行：

```bash
python3 -m unittest discover -s tests -v
```

预期：所有测试 PASS。

- [ ] **步骤 4：运行真实 audit dry-run smoke**

运行：

```bash
python3 scripts/audit_training_pipeline.py --input-root /isos_data_share/audit --output-root audit_training --date 2026-07-16 --limit 100 --dry-run
```

预期：命令退出码为 0，stdout 输出一行 JSON，包含 `"accepted"`、`"rejected"`、`"dry_run": true`。不得在日志或 stdout 中输出用户消息正文。

- [ ] **步骤 5：运行小规模真实写入 smoke**

运行：

```bash
python3 scripts/audit_training_pipeline.py --input-root /isos_data_share/audit --output-root audit_training --date 2026-07-16 --limit 100
```

预期：命令退出码为 0，并生成：

```text
audit_training/canonical/2026-07-16.jsonl
audit_training/sft/2026-07-16.jsonl
audit_training/tool_use_sft/2026-07-16.jsonl
audit_training/router_classification/2026-07-16.jsonl
audit_training/reports/2026-07-16.stats.json
audit_training/manifests/2026-07-16.manifest.json
```

运行 JSONL 可解析检查：

```bash
python3 -m json.tool audit_training/reports/2026-07-16.stats.json >/tmp/audit_stats_check.json
python3 -m json.tool audit_training/manifests/2026-07-16.manifest.json >/tmp/audit_manifest_check.json
```

预期：两个命令退出码为 0。

- [ ] **步骤 6：确认 Git 只跟踪工程文件**

运行：

```bash
git status --short
```

预期：只出现 `scripts/audit_training_pipeline.py`、`tests/test_audit_training_pipeline.py`、`audit_training/README.md`、计划或文档文件；不出现 `audit_training/canonical/`、`audit_training/sft/` 等生成数据。

- [ ] **步骤 7：Commit 并推送**

```bash
git add scripts/audit_training_pipeline.py tests/test_audit_training_pipeline.py audit_training/README.md docs/superpowers/plans/2026-07-16-audit-training-data-pipeline-implementation.md
git commit -m "feat: add audit training data pipeline"
git push
```

预期：push 成功到 `origin/main`。

## 规格覆盖自检清单

- Canonical-first：任务 4 和任务 7 覆盖。
- 默认脱敏：任务 2 和任务 4 覆盖。
- 普通 SFT：任务 5 覆盖。
- Tool-use SFT：任务 5 覆盖。
- Router classification：任务 5 覆盖。
- 可选 OpenAI-compatible 标注：任务 6 覆盖。
- 每日昨天分区、日期范围、limit、dry-run：任务 8 覆盖。
- 原子写入、manifest、stats、rejects、label queue：任务 7 覆盖。
- 不提交大数据输出：任务 8 和现有 `.gitignore` 覆盖。
