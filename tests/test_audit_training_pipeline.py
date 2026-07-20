import contextlib
import copy
import importlib.util
import io
import json
import math
import os
import pathlib
import sys
import tempfile
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
        self.assertEqual(pipeline.PIPELINE_VERSION, "2026.07.19")

    def test_readme_documents_selected_outputs_and_explicit_labelers(self):
        readme = (REPO_ROOT / "audit_training" / "README.md").read_text(encoding="utf-8")
        script = REPO_ROOT / "scripts" / "run_audit_training_pipeline.sh"
        self.assertTrue(script.exists())
        for token in [
            "selected/sft/<date>.jsonl",
            "quality/<date>.jsonl",
            "episodes/<date>.jsonl",
            "--enable-route-labeler",
            "--enable-quality-labeler",
            "--enable-label-snippets",
            "--disable-selection",
            "--compat-output-set",
            "--disable-dedupe",
            "--disable-near-duplicate-dedupe",
            "--disable-debug-noise-filter",
            "dedupe",
            "debug noise",
            "quality_stats",
            "dedupe_rejected",
            "risk_labels",
            "dedupe_enabled",
            "dedupe_config",
            "final exact seen guard",
            "exact duplicate",
            "normalized duplicate",
            "near duplicate",
            "debug burst",
            "raw prompts/responses",
            "tenant/user/session hashes",
            "internal dedupe hash fields",
            "AUDIT_SELECTION_HMAC_KEY",
        ]:
            self.assertIn(token, readme)
        self.assertIn("Environment variables alone do not trigger external calls", readme)


class CliTest(unittest.TestCase):
    def test_date_range_returns_inclusive_dates(self):
        pipeline = load_pipeline_module()
        self.assertEqual(
            pipeline.date_range("2026-07-01", "2026-07-03"),
            ["2026-07-01", "2026-07-02", "2026-07-03"],
        )

    def test_resolve_dates_accepts_single_date(self):
        pipeline = load_pipeline_module()
        args = pipeline.parse_args(["--date", "2026-07-15"])
        self.assertEqual(pipeline.resolve_dates(args), ["2026-07-15"])

    def test_resolve_dates_accepts_inclusive_start_and_end(self):
        pipeline = load_pipeline_module()
        args = pipeline.parse_args(
            ["--start-date", "2026-07-01", "--end-date", "2026-07-03"]
        )
        self.assertEqual(
            pipeline.resolve_dates(args),
            ["2026-07-01", "2026-07-02", "2026-07-03"],
        )

    def test_resolve_dates_requires_date_selector(self):
        pipeline = load_pipeline_module()
        args = pipeline.parse_args([])
        with self.assertRaises(SystemExit):
            pipeline.resolve_dates(args)

    def test_resolve_dates_rejects_invalid_single_date(self):
        pipeline = load_pipeline_module()
        args = pipeline.parse_args(["--date", "2026-7-1"])
        with self.assertRaises(SystemExit):
            pipeline.resolve_dates(args)

    def test_date_range_rejects_non_strict_dates(self):
        pipeline = load_pipeline_module()
        with self.assertRaises(ValueError):
            pipeline.date_range("2026-7-1", "2026-07-02")

    def test_main_processes_each_date_and_prints_json_lines(self):
        pipeline = load_pipeline_module()
        calls = []

        def fake_process_date(input_root, output_root, date, limit=None, dry_run=False, **kwargs):
            calls.append((input_root, output_root, date, limit, dry_run))
            return {"date": date, "accepted": 1}

        pipeline.process_date = fake_process_date
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = pipeline.main(
                [
                    "--input-root",
                    "in",
                    "--output-root",
                    "out",
                    "--start-date",
                    "2026-07-01",
                    "--end-date",
                    "2026-07-02",
                    "--limit",
                    "5",
                    "--dry-run",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            calls,
            [
                ("in", "out", "2026-07-01", 5, True),
                ("in", "out", "2026-07-02", 5, True),
            ],
        )
        lines = stdout.getvalue().splitlines()
        self.assertEqual(
            [json.loads(line) for line in lines],
            [
                {"accepted": 1, "date": "2026-07-01"},
                {"accepted": 1, "date": "2026-07-02"},
            ],
        )

    def test_main_empty_argv_does_not_fall_back_to_sys_argv(self):
        pipeline = load_pipeline_module()
        calls = []

        def fake_process_date(input_root, output_root, date, limit=None, dry_run=False, **kwargs):
            calls.append(date)
            return {"date": date}

        pipeline.process_date = fake_process_date
        original_argv = sys.argv
        sys.argv = ["audit_training_pipeline.py", "--date", "2099-01-01"]
        try:
            with self.assertRaises(SystemExit):
                pipeline.main([])
        finally:
            sys.argv = original_argv
        self.assertEqual(calls, [])

    def test_resolve_dates_rejects_conflicting_selectors(self):
        pipeline = load_pipeline_module()
        args = pipeline.parse_args(["--date", "2026-07-01", "--yesterday"])
        with self.assertRaises(SystemExit):
            pipeline.resolve_dates(args)

    def test_resolve_dates_rejects_reversed_range(self):
        pipeline = load_pipeline_module()
        args = pipeline.parse_args(
            ["--start-date", "2026-07-03", "--end-date", "2026-07-01"]
        )
        with self.assertRaises(SystemExit):
            pipeline.resolve_dates(args)

    def test_parse_args_rejects_negative_limit(self):
        pipeline = load_pipeline_module()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                pipeline.parse_args(["--date", "2026-07-01", "--limit", "-1"])

    def test_main_rejects_non_standard_json_stdout(self):
        pipeline = load_pipeline_module()

        def fake_process_date(input_root, output_root, date, limit=None, dry_run=False, **kwargs):
            return {"date": date, "score": math.nan}

        pipeline.process_date = fake_process_date
        with self.assertRaises(ValueError):
            pipeline.main(["--date", "2026-07-01"])


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
        self.assertEqual(stats["phone"], 1)
        self.assertGreaterEqual(stats["email"], 1)
        self.assertGreaterEqual(stats["cn_id"], 1)
        self.assertGreaterEqual(stats["secret"], 1)

    def test_redact_text_preserves_space_between_bank_card_and_ip_tokens(self):
        pipeline = load_pipeline_module()
        text = "card 6222 0202 0202 0202 020 ip 192.168.0.1"
        redacted, stats = pipeline.redact_text(text)
        self.assertIn("<BANK_CARD_1> ip <IP_1>", redacted)
        self.assertGreaterEqual(stats["bank_card"], 1)
        self.assertGreaterEqual(stats["ip"], 1)

    def test_redact_text_prefers_secret_over_numeric_value_patterns(self):
        pipeline = load_pipeline_module()
        text = "api_key=1234567890123456"
        redacted, stats = pipeline.redact_text(text)
        self.assertIn("<SECRET_1>", redacted)
        self.assertNotIn("<BANK_CARD_1>", redacted)
        self.assertEqual(stats["secret"], 1)

    def test_hash_identifier_is_deterministic_and_not_plaintext(self):
        pipeline = load_pipeline_module()
        first = pipeline.hash_identifier("tenant-123")
        second = pipeline.hash_identifier("tenant-123")
        other = pipeline.hash_identifier("tenant-456")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertNotIn("tenant-123", first)
        self.assertEqual(len(first), 16)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def read_jsonl(path):
    text = path.read_text(encoding="utf-8")
    if not text:
        return []
    return [json.loads(line) for line in text.splitlines()]


def write_index(day, entries):
    day.mkdir(parents=True, exist_ok=True)
    (day / "_request_index.jsonl").write_text(
        "".join(json.dumps(entry, ensure_ascii=False) + "\n" for entry in entries),
        encoding="utf-8",
    )


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
                "{\"request_id\":NaN,\"file_path\":\"2026-07-15/u/s/nan.json\"}\n"
                "[]\n"
                "{\"request_id\":123,\"file_path\":\"2026-07-15/u/s/number.json\"}\n"
                "{\"request_id\":\"bad-path\",\"file_path\":123}\n"
                "{\"request_id\":\"r2\",\"file_path\":\"2026-07-15/u/s/002.json\"}\n",
                encoding="utf-8",
            )
            events = list(pipeline.iter_index_records(root, "2026-07-15"))
            records = [record for record, error in events if record is not None]
            errors = [error for record, error in events if error is not None]
            self.assertEqual([record["request_id"] for record in records], ["r1", "r2"])
            self.assertEqual(
                [error["reason"] for error in errors],
                [
                    "bad_index_json",
                    "bad_index_json",
                    "bad_index_record",
                    "bad_index_record",
                    "bad_index_record",
                ],
            )

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



    def test_load_audit_record_rejects_non_standard_json_constants(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            detail_path = root / "2026-07-15" / "u" / "s" / "001.json"
            detail_path.parent.mkdir(parents=True)
            detail_path.write_text('{"request_id":"r1","value":NaN}', encoding="utf-8")
            loaded, error = pipeline.load_audit_record(
                root,
                {"request_id": "r1", "file_path": "2026-07-15/u/s/001.json"},
            )
            self.assertIsNone(loaded)
            self.assertEqual(error["reason"], "bad_detail_json")



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
        self.assertIn("file_path_hash", canonical["source"])
        self.assertNotIn("file_path", canonical["source"])
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


    def test_build_canonical_sample_filters_direct_identifier_params(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"].update(
            {
                "user": "request-body-user",
                "tenant_id": "request-body-tenant",
                "session_id": "request-body-session",
                "api_key_id": "request-body-api-key",
                "client_ip": "203.0.113.9",
                "temperature": 0.7,
                "top_p": 0.8,
                "max_tokens": 128,
            }
        )
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        dumped = json.dumps(canonical, ensure_ascii=False)
        self.assertNotIn("request-body-user", dumped)
        self.assertNotIn("request-body-tenant", dumped)
        self.assertNotIn("request-body-session", dumped)
        self.assertNotIn("request-body-api-key", dumped)
        self.assertNotIn("203.0.113.9", dumped)
        self.assertEqual(canonical["request"]["params"]["temperature"], 0.7)
        self.assertEqual(canonical["request"]["params"]["top_p"], 0.8)
        self.assertEqual(canonical["request"]["params"]["max_tokens"], 128)
        self.assertEqual(canonical["request"]["params"]["client_type"], "opencode")
        self.assertEqual(canonical["request"]["params"]["is_stream"], False)

    def test_build_canonical_sample_rejects_oversized_tool_call_response(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["response_body"]["choices"][0]["message"] = {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "x" * 64},
                }
            ],
        }
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
            max_response_chars=20,
        )
        self.assertIsNone(canonical)
        self.assertEqual(reject["reason"], "response_too_long")

    def test_build_canonical_sample_accepts_multipart_assistant_text(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["response_body"]["choices"][0]["message"]["content"] = [
            {"type": "text", "text": "可以联系 13800138000"}
        ]
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        self.assertIn(
            "<PHONE_1>",
            canonical["response"]["message"]["content"][0]["text"],
        )

    def test_build_canonical_sample_rejects_non_list_choices(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["response_body"]["choices"] = {"0": raw["response_body"]["choices"][0]}
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(canonical)
        self.assertEqual(reject["reason"], "missing_choices")

    def test_build_canonical_sample_rejects_empty_choices(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["response_body"]["choices"] = []
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(canonical)
        self.assertEqual(reject["reason"], "missing_choices")

    def test_build_canonical_sample_rejects_non_dict_first_choice(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["response_body"]["choices"] = ["not-a-dict"]
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(canonical)
        self.assertEqual(reject["reason"], "missing_choices")

    def test_build_canonical_sample_rejects_non_dict_request_body(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"] = "not a request object"
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(canonical)
        self.assertEqual(reject["reason"], "missing_messages")

    def test_build_canonical_sample_rejects_dict_message_content(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["messages"] = [
            {"role": "user", "content": {"prompt": "do not accept dict content"}}
        ]
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(canonical)
        self.assertEqual(reject["reason"], "invalid_messages")

    def test_build_canonical_sample_redacts_request_params_values(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"].update(
            {
                "stop": ["secret@example.com"],
                "response_format": {"note": "联系 13800138000"},
                "tool_choice": {"function": {"name": "api_key=abcdefghijklmnopqrstuvwxyz123456"}},
                "user": "request-body-user",
            }
        )
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        dumped = json.dumps(canonical, ensure_ascii=False)
        self.assertNotIn("secret@example.com", dumped)
        self.assertNotIn("13800138000", dumped)
        self.assertNotIn("api_key=abcdefghijklmnopqrstuvwxyz123456", dumped)
        self.assertNotIn("request-body-user", dumped)
        self.assertIn("<EMAIL_1>", canonical["request"]["params"]["stop"][0])
        self.assertIn(
            "<PHONE_1>", canonical["request"]["params"]["response_format"]["note"]
        )
        self.assertIn(
            "<SECRET_1>",
            canonical["request"]["params"]["tool_choice"]["function"]["name"],
        )
        self.assertTrue(canonical["quality"]["pii_redacted"])
        self.assertGreaterEqual(canonical["quality"]["redaction_stats"]["email"], 1)
        self.assertGreaterEqual(canonical["quality"]["redaction_stats"]["phone"], 1)
        self.assertGreaterEqual(canonical["quality"]["redaction_stats"]["secret"], 1)

    def test_build_canonical_sample_redacts_sensitive_values_across_payload(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"].update(
            {
                "messages": [
                    {"role": "user", "content": "call me 13800138000"}
                ],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "lookup",
                            "description": "联系 13900139000",
                        },
                    }
                ],
                "stop": ["secret@example.com"],
            }
        )
        raw["response_body"]["choices"][0]["message"]["content"] = (
            "Bearer sk-abcdefghijklmnopqrstuvwxyz1234567890"
        )
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        dumped = json.dumps(canonical, ensure_ascii=False)
        self.assertNotIn("13800138000", dumped)
        self.assertNotIn("13900139000", dumped)
        self.assertNotIn("secret@example.com", dumped)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz1234567890", dumped)
        self.assertTrue(canonical["quality"]["pii_redacted"])

    def test_build_canonical_sample_hashes_are_deterministic(self):
        pipeline = load_pipeline_module()
        index = {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}
        first, first_reject = pipeline.build_canonical_sample(
            "2026-07-15", index, sample_success_record()
        )
        second, second_reject = pipeline.build_canonical_sample(
            "2026-07-15", index, sample_success_record()
        )
        self.assertIsNone(first_reject)
        self.assertIsNone(second_reject)
        self.assertEqual(first["sample_id"], second["sample_id"])
        self.assertEqual(
            first["quality"]["content_hash"], second["quality"]["content_hash"]
        )

    def test_build_canonical_sample_marks_tool_use_task_type(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["tools"] = [
            {
                "type": "function",
                "function": {"name": "lookup", "parameters": {"type": "object"}},
            }
        ]
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        self.assertIn("tool_use_sft", canonical["quality"]["task_types"])

    def test_build_canonical_sample_rejects_long_prompt(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["messages"] = [{"role": "user", "content": "x" * 32}]
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
            max_prompt_chars=10,
        )
        self.assertIsNone(canonical)
        self.assertEqual(reject["reason"], "prompt_too_long")


    def test_build_canonical_sample_rejects_invalid_usage_values(self):
        pipeline = load_pipeline_module()
        invalid_usages = [
            "not-a-dict",
            {"prompt_tokens": "10"},
            {"prompt_tokens": True},
            {"prompt_tokens": float("nan")},
            {"prompt_tokens": float("inf")},
            {"prompt_tokens": -1},
            {"prompt_tokens": 1.5},
        ]
        for usage in invalid_usages:
            with self.subTest(usage=usage):
                raw = sample_success_record()
                raw["response_body"]["usage"] = usage
                canonical, reject = pipeline.build_canonical_sample(
                    "2026-07-15",
                    {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
                    raw,
                )
                self.assertIsNone(canonical)
                self.assertEqual(reject["reason"], "invalid_usage")

    def test_sanitize_usage_rejects_oversized_int_without_overflow(self):
        pipeline = load_pipeline_module()
        self.assertIsNone(pipeline.sanitize_usage({"prompt_tokens": 10 ** 10000}))
        self.assertIsNone(pipeline.sanitize_usage({"prompt_tokens": -(10 ** 10000)}))

    def test_build_canonical_sample_keeps_only_sanitized_usage_token_fields(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["response_body"]["usage"] = {
            "prompt_tokens": 10.0,
            "completion_tokens": 5,
            "total_tokens": 15,
            "debug": "secret@example.com",
        }
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        self.assertEqual(
            canonical["response"]["usage"],
            {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        )

    def test_build_canonical_sample_rejects_invalid_message_schema(self):
        pipeline = load_pipeline_module()
        cases = [
            (["not-a-dict"], "invalid_messages"),
            ([{"role": 123, "content": "hello"}], "invalid_messages"),
            ([{"role": "user"}], "invalid_messages"),
            ([{"role": "user", "content": [{"text": 123}]}], "invalid_messages"),
        ]
        for messages, reason in cases:
            with self.subTest(messages=messages):
                raw = sample_success_record()
                raw["request_body"]["messages"] = messages
                canonical, reject = pipeline.build_canonical_sample(
                    "2026-07-15",
                    {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
                    raw,
                )
                self.assertIsNone(canonical)
                self.assertEqual(reject["reason"], reason)

    def test_build_canonical_sample_rejects_invalid_tools_and_tool_calls(self):
        pipeline = load_pipeline_module()
        invalid_tools = [
            {"bad": "shape"},
            [{}],
            [{"type": "function"}],
            [{"type": "function", "function": {}}],
            [{"type": "function", "function": {"name": ""}}],
            [{"type": "function", "function": {"name": "search", "description": 123}}],
            [{"type": "function", "function": {"name": "search", "parameters": "not-object"}}],
            [{"type": "function", "function": {"name": "search", "parameters": []}}],
            [{"type": "retrieval", "function": {"name": "search"}}],
        ]
        for tools in invalid_tools:
            with self.subTest(tools=tools):
                raw = sample_success_record()
                raw["request_body"]["tools"] = tools
                canonical, reject = pipeline.build_canonical_sample(
                    "2026-07-15",
                    {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
                    raw,
                )
                self.assertIsNone(canonical)
                self.assertEqual(reject["reason"], "invalid_tools")

        invalid_tool_calls = [
            ["bad"],
            [{}],
            [{"id": "call_1", "type": "function", "function": {}}],
            [{"id": "", "type": "function", "function": {"name": "search"}}],
            [{"id": "call_1", "type": "retrieval", "function": {"name": "search"}}],
            [{"id": "call_1", "type": "function", "function": {"name": "search"}}],
            [{"id": "call_1", "type": "function", "function": {"name": "search", "arguments": {}}}],
        ]
        for tool_calls in invalid_tool_calls:
            with self.subTest(tool_calls=tool_calls):
                raw = sample_success_record()
                raw["response_body"]["choices"][0]["message"]["tool_calls"] = tool_calls
                canonical, reject = pipeline.build_canonical_sample(
                    "2026-07-15",
                    {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
                    raw,
                )
                self.assertIsNone(canonical)
                self.assertEqual(reject["reason"], "invalid_response_message")

    def test_build_canonical_sample_accepts_valid_tool_and_tool_call_shapes(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": "search",
                    "description": "Search docs",
                    "parameters": {"type": "object"},
                },
            }
        ]
        raw["response_body"]["choices"][0]["finish_reason"] = "tool_calls"
        raw["response_body"]["choices"][0]["message"] = {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "search", "arguments": ""},
                }
            ],
        }
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        self.assertIn("tool_use_sft", canonical["quality"]["task_types"])


    def test_build_canonical_sample_accepts_null_content_with_valid_tool_calls(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["tools"] = [
            {"type": "function", "function": {"name": "search"}}
        ]
        raw["response_body"]["choices"][0]["finish_reason"] = "tool_calls"
        raw["response_body"]["choices"][0]["message"] = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "search", "arguments": "{}"},
                }
            ],
        }
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        self.assertIn("tool_use_sft", canonical["quality"]["task_types"])
        exported = pipeline.export_tool_use_sft(canonical)
        self.assertEqual(exported["response_message"]["tool_calls"][0]["id"], "call_1")


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
        canonical["request"]["tools"] = [
            {"type": "function", "function": {"name": "search"}}
        ]
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
        raw["request_body"]["tools"] = [
            {"type": "function", "function": {"name": "search"}}
        ]
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

    def test_export_sft_skips_tool_calls_and_length_outputs(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["response"]["message"]["tool_calls"] = [{"id": "call_1"}]
        self.assertIsNone(pipeline.export_sft(canonical))
        canonical["response"]["message"].pop("tool_calls")
        canonical["response"]["finish_reason"] = "length"
        self.assertIsNone(pipeline.export_sft(canonical))

    def test_export_tool_use_sft_skips_non_tool_samples(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        self.assertIsNone(pipeline.export_tool_use_sft(canonical))


    def test_export_sft_extracts_multipart_assistant_text(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["response_body"]["choices"][0]["message"]["content"] = [
            {"type": "text", "text": "hello"},
            {"type": "image_url", "image_url": {"url": "https://example.invalid/a.png"}},
            {"text": "world"},
        ]
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        exported = pipeline.export_sft(canonical)
        self.assertEqual(exported["output"], "hello\nworld")
        self.assertNotIn("[{", exported["output"])
        self.assertNotIn("'type'", exported["output"])

    def test_export_sft_skips_non_text_assistant_content(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["response"]["message"]["content"] = {"text": "do not repr"}
        self.assertIsNone(pipeline.export_sft(canonical))

    def test_last_user_content_ignores_dict_and_router_avoids_repr(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["request"]["messages"] = [
            {"role": "user", "content": {"prompt": "python code"}}
        ]
        router = pipeline.export_router(canonical)
        self.assertEqual(pipeline.last_user_content(canonical["request"]["messages"]), "")
        self.assertEqual(router["input"], "")
        self.assertNotIn("{'prompt'", router["input"])

    def test_multipart_user_content_drives_rule_classification(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["request"]["messages"] = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "请分析这个问题"},
                    {"type": "image_url", "image_url": {"url": "https://example.invalid/a.png"}},
                ],
            }
        ]
        self.assertEqual(pipeline.last_user_content(canonical["request"]["messages"]), "请分析这个问题")
        self.assertEqual(pipeline.classify_by_rules(canonical), "reasoning")

    def test_export_tool_use_sft_skips_length_outputs(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["tools"] = [
            {"type": "function", "function": {"name": "search"}}
        ]
        raw["response_body"]["choices"][0]["finish_reason"] = "length"
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        self.assertIsNone(pipeline.export_tool_use_sft(canonical))

    def test_export_router_ignores_malformed_model_label_confidence(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["routing"]["model_label"] = {"label": "tool_agent", "confidence": "0.9"}
        router = pipeline.export_router(canonical)
        self.assertEqual(router["labels"]["rule_label"], "code_generation")
        self.assertEqual(router["labels"]["final_label"], "code_generation")
        canonical["routing"]["model_label"] = {"label": "tool_agent", "confidence": None}
        router = pipeline.export_router(canonical)
        self.assertEqual(router["labels"]["final_label"], "code_generation")
        self.assertEqual(router["labels"]["confidence"], "medium")

    def test_export_router_ignores_malformed_model_label_types(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        for bad_label in ([], {}):
            with self.subTest(label=bad_label):
                canonical["routing"]["model_label"] = {
                    "label": bad_label,
                    "confidence": 0.9,
                }
                router = pipeline.export_router(canonical)
                self.assertEqual(router["labels"]["final_label"], "code_generation")
                self.assertEqual(router["labels"]["confidence"], "medium")
        canonical["routing"]["model_label"] = {"label": "tool_agent", "confidence": True}
        router = pipeline.export_router(canonical)
        self.assertEqual(router["labels"]["final_label"], "code_generation")
        self.assertEqual(router["labels"]["confidence"], "medium")
        self.assertIsNone(router["labels"]["model_label"])

    def test_export_router_sanitizes_malformed_model_label_payload(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["routing"]["model_label"] = {
            "label": [],
            "confidence": 0.9,
            "debug": "raw prompt secret@example.com",
        }
        router = pipeline.export_router(canonical)
        dumped = json.dumps(router, ensure_ascii=False)
        self.assertIsNone(router["labels"]["model_label"])
        self.assertEqual(router["labels"]["final_label"], "code_generation")
        self.assertNotIn("debug", dumped)
        self.assertNotIn("raw prompt", dumped)
        self.assertNotIn("secret@example.com", dumped)

    def test_export_router_uses_sanitized_high_confidence_model_label(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["routing"]["model_label"] = {
            "label": "tool_agent",
            "confidence": 0.75,
            "reason": "debug reason should stay out",
        }
        router = pipeline.export_router(canonical)
        self.assertEqual(router["labels"]["final_label"], "tool_agent")
        self.assertEqual(router["labels"]["confidence"], "high")
        self.assertEqual(
            router["labels"]["model_label"],
            {"label": "tool_agent", "confidence": 0.75},
        )
        self.assertNotIn("reason", json.dumps(router, ensure_ascii=False))

    def test_export_router_preserves_sanitized_low_confidence_model_label(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["routing"]["model_label"] = {"label": "tool_agent", "confidence": 0.74}
        router = pipeline.export_router(canonical)
        self.assertEqual(router["labels"]["final_label"], "tool_agent")
        self.assertEqual(router["labels"]["confidence"], "low")
        self.assertEqual(
            router["labels"]["model_label"],
            {"label": "tool_agent", "confidence": 0.74},
        )

    def test_collect_outputs_queues_low_confidence_model_label(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["routing"]["model_label"] = {"label": "tool_agent", "confidence": 0.74}
        outputs = pipeline.collect_outputs(
            "2026-07-15",
            [canonical],
            [],
            [],
            {"accepted": 1, "rejected": 0},
            {"accepted": 1, "rejected": 0},
        )
        queue = outputs["label_queue/2026-07-15.jsonl"]
        self.assertEqual(len(queue), 1)
        dumped = json.dumps(queue[0], ensure_ascii=False)
        self.assertEqual(queue[0]["reason"], "low_confidence_route")
        self.assertIn("features", queue[0])
        self.assertNotIn("sample_id", dumped)
        self.assertNotIn("input", dumped)
        self.assertNotIn("router", dumped)


    def test_export_sft_rebuilds_messages_as_text_only(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["messages"] = [
            {
                "role": "system",
                "content": "",
            },
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "请写 Python 代码"},
                    {"type": "image_url", "image_url": {"url": "https://example.invalid/a.png"}},
                ],
            },
        ]
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        exported = pipeline.export_sft(canonical)
        dumped = json.dumps(exported, ensure_ascii=False)
        self.assertEqual(
            exported["messages"],
            [
                {"role": "user", "content": "请写 Python 代码"},
                {"role": "assistant", "content": "可以使用 print('hello')"},
            ],
        )
        self.assertNotIn("image_url", dumped)
        self.assertNotIn("debug", dumped)
        for message in exported["messages"]:
            self.assertIsInstance(message["content"], str)

    def test_export_sft_skips_when_no_user_text_message(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["request"]["messages"] = [
            {"role": "user", "content": {"prompt": "do not repr"}}
        ]
        self.assertIsNone(pipeline.export_sft(canonical))

    def test_export_router_rejects_non_finite_or_out_of_range_model_confidence(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        for confidence in (float("nan"), float("inf"), -0.1, 1.5):
            with self.subTest(confidence=confidence):
                canonical["routing"]["model_label"] = {
                    "label": "tool_agent",
                    "confidence": confidence,
                }
                router = pipeline.export_router(canonical)
                self.assertIsNone(router["labels"]["model_label"])
                self.assertEqual(router["labels"]["final_label"], "code_generation")
                self.assertEqual(router["labels"]["confidence"], "medium")

    def test_exporters_skip_non_dict_messages(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["request"]["messages"] = [
            {"role": "user", "content": "请写 Python 代码"},
            "bad-message",
            None,
        ]
        self.assertEqual(pipeline.classify_by_rules(canonical), "code_generation")
        router = pipeline.export_router(canonical)
        sft = pipeline.export_sft(canonical)
        self.assertEqual(router["input"], "请写 Python 代码")
        self.assertEqual(sft["input"], "请写 Python 代码")
        self.assertEqual(sft["messages"][0], {"role": "user", "content": "请写 Python 代码"})


class LabelModelTest(unittest.TestCase):
    def test_parse_label_response_accepts_controlled_json(self):
        pipeline = load_pipeline_module()
        parsed = pipeline.parse_label_response('{"label":"tool_agent","confidence":0.82,"reason":"uses tools"}')
        self.assertEqual(parsed["label"], "tool_agent")
        self.assertEqual(parsed["confidence"], 0.82)
        self.assertEqual(parsed["reason"], "uses tools")

    def test_parse_label_response_rejects_unknown_label(self):
        pipeline = load_pipeline_module()
        parsed = pipeline.parse_label_response('{"label":"bad_label","confidence":0.99,"reason":"no"}')
        self.assertIsNone(parsed)

    def test_parse_label_response_rejects_malformed_or_non_object_json(self):
        pipeline = load_pipeline_module()
        self.assertIsNone(pipeline.parse_label_response("{bad json}"))
        self.assertIsNone(pipeline.parse_label_response("[]"))

    def test_parse_label_response_rejects_unsafe_confidence_values(self):
        pipeline = load_pipeline_module()
        for confidence in ("0.9", True, float("nan"), float("inf"), -0.1, 1.1):
            with self.subTest(confidence=confidence):
                text = json.dumps(
                    {"label": "tool_agent", "confidence": confidence, "reason": "no"},
                    allow_nan=True,
                )
                self.assertIsNone(pipeline.parse_label_response(text))

    def test_parse_label_response_rejects_non_string_reason(self):
        pipeline = load_pipeline_module()
        for reason in ({"why": "tools"}, ["tools"]):
            with self.subTest(reason=reason):
                text = json.dumps(
                    {"label": "tool_agent", "confidence": 0.82, "reason": reason},
                    ensure_ascii=False,
                )
                self.assertIsNone(pipeline.parse_label_response(text))

    def test_parse_label_response_allows_missing_reason(self):
        pipeline = load_pipeline_module()
        parsed = pipeline.parse_label_response(
            '{"label":"tool_agent","confidence":0.82}'
        )
        self.assertEqual(parsed["reason"], "")

    def test_label_config_reads_environment(self):
        pipeline = load_pipeline_module()
        env = {
            "AUDIT_LABEL_BASE_URL": "https://example.test/v1",
            "AUDIT_LABEL_API_KEY": "key",
            "AUDIT_LABEL_MODEL": "label-model",
            "AUDIT_LABEL_TIMEOUT": "12",
        }
        config = pipeline.load_label_config(env)
        self.assertTrue(config["enabled"])
        self.assertEqual(config["timeout"], 12)
        self.assertNotIn("max_concurrency", config)

    def test_label_config_disables_when_required_values_are_missing(self):
        pipeline = load_pipeline_module()
        config = pipeline.load_label_config(
            {
                "AUDIT_LABEL_BASE_URL": "https://example.test/v1",
                "AUDIT_LABEL_API_KEY": "key",
            }
        )
        self.assertFalse(config["enabled"])

    def test_label_config_clamps_and_defaults_numbers(self):
        pipeline = load_pipeline_module()
        base_env = {
            "AUDIT_LABEL_BASE_URL": "https://example.test/v1/",
            "AUDIT_LABEL_API_KEY": "key",
            "AUDIT_LABEL_MODEL": "label-model",
        }
        config = pipeline.load_label_config(dict(base_env, AUDIT_LABEL_TIMEOUT="999999"))
        self.assertTrue(config["enabled"])
        self.assertEqual(config["base_url"], "https://example.test/v1")
        self.assertEqual(config["timeout"], 120)

        config = pipeline.load_label_config(dict(base_env, AUDIT_LABEL_TIMEOUT="-5"))
        self.assertEqual(config["timeout"], 1)

        config = pipeline.load_label_config(dict(base_env, AUDIT_LABEL_TIMEOUT="bad"))
        self.assertEqual(config["timeout"], 30)

    def test_call_label_model_disabled_returns_reason(self):
        pipeline = load_pipeline_module()
        parsed, error = pipeline.call_label_model({}, {"enabled": False})
        self.assertIsNone(parsed)
        self.assertEqual(error, "labeler_disabled")

    def test_call_label_model_parses_successful_response(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        payload, payload_error = pipeline.build_route_label_payload(canonical, allow_snippets=False)
        self.assertIsNone(payload_error)
        calls = []

        class FakeResponse(object):
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return json.dumps(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": '{"label":"tool_agent","confidence":0.91,"reason":"tools"}'
                                }
                            }
                        ]
                    }
                ).encode("utf-8")

        def fake_urlopen(request, timeout=None):
            calls.append((request, timeout))
            self.assertEqual(request.full_url, "https://example.test/v1/chat/completions")
            self.assertEqual(request.get_header("Authorization"), "Bearer key")
            self.assertEqual(request.get_header("Content-type"), "application/json")
            body = json.loads(request.data.decode("utf-8"))
            self.assertEqual(body["model"], "label-model")
            self.assertEqual(body["temperature"], 0)
            prompt = json.loads(body["messages"][1]["content"])
            dumped = json.dumps(prompt, ensure_ascii=False)
            self.assertEqual(prompt["task"], "classify_route")
            self.assertIn("tool_agent", prompt["labels"])
            self.assertIn("features", prompt["sample"])
            self.assertNotIn("input", dumped)
            self.assertNotIn("messages", dumped)
            self.assertNotIn("sample_id", dumped)
            self.assertNotIn("request-1", dumped)
            self.assertNotIn("tenant_hash", dumped)
            self.assertNotIn("13800138000", dumped)
            return FakeResponse()

        config = {
            "enabled": True,
            "base_url": "https://example.test/v1",
            "api_key": "key",
            "model": "label-model",
            "timeout": 12,
        }
        parsed, error = pipeline.call_label_model(
            payload, config, urlopen=fake_urlopen
        )
        self.assertIsNone(error)
        self.assertEqual(parsed["label"], "tool_agent")
        self.assertEqual(parsed["confidence"], 0.91)
        self.assertEqual(calls[0][1], 12)

    def test_call_label_model_rejects_invalid_response(self):
        pipeline = load_pipeline_module()

        class FakeResponse(object):
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return json.dumps(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": '{"label":"bad_label","confidence":0.91,"reason":"no"}'
                                }
                            }
                        ]
                    }
                ).encode("utf-8")

        def fake_urlopen(request, timeout=None):
            return FakeResponse()

        config = {
            "enabled": True,
            "base_url": "https://example.test/v1",
            "api_key": "key",
            "model": "label-model",
            "timeout": 12,
        }
        parsed, error = pipeline.call_label_model({}, config, urlopen=fake_urlopen)
        self.assertIsNone(parsed)
        self.assertEqual(error, "labeler_invalid_response")


    def test_call_label_model_rejects_malformed_response_shapes(self):
        pipeline = load_pipeline_module()
        config = {
            "enabled": True,
            "base_url": "https://example.test/v1",
            "api_key": "key",
            "model": "label-model",
            "timeout": 12,
        }
        malformed_payloads = [
            [],
            {"choices": {"unexpected": "shape"}},
            {"choices": 1},
            {"choices": "bad"},
            {"choices": []},
            {"choices": ["not-a-dict"]},
            {"choices": [{"message": "not-a-dict"}]},
            {"choices": [{"message": {"content": {"label": "tool_agent"}}}]},
        ]

        class FakeResponse(object):
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return json.dumps(self.payload).encode("utf-8")

        for payload in malformed_payloads:
            with self.subTest(payload=payload):
                def fake_urlopen(request, timeout=None, payload=payload):
                    return FakeResponse(payload)

                parsed, error = pipeline.call_label_model(
                    {}, config, urlopen=fake_urlopen
                )
                self.assertIsNone(parsed)
                self.assertEqual(error, "labeler_invalid_response")



class SelectionPipelineTest(unittest.TestCase):
    FORBIDDEN_SELECTED_KEYS = set([
        "sample_id",
        "request_id",
        "file_path_hash",
        "tenant_hash",
        "user_hash",
        "session_hash",
        "task_fingerprint_internal",
        "content_hash",
        "index_order",
    ])

    def assert_no_forbidden_selected_fields(self, value):
        if isinstance(value, dict):
            for key, item in value.items():
                self.assertNotIn(key, self.FORBIDDEN_SELECTED_KEYS)
                self.assert_no_forbidden_selected_fields(item)
        elif isinstance(value, list):
            for item in value:
                self.assert_no_forbidden_selected_fields(item)

    def test_parse_args_accepts_selection_controls_and_rejects_conflicts(self):
        pipeline = load_pipeline_module()
        args = pipeline.parse_args([
            "--date", "2026-07-15",
            "--disable-episodes",
            "--selection-mode", "spool",
            "--max-in-memory-samples", "0",
            "--max-selection-memory-mb", "1",
            "--enable-route-labeler",
            "--enable-quality-labeler",
            "--enable-label-snippets",
            "--disable-dedupe",
            "--disable-near-duplicate-dedupe",
            "--disable-debug-noise-filter",
            "--near-duplicate-simhash-hamming", "5",
            "--near-duplicate-jaccard", "0.9",
            "--near-duplicate-min-chars", "32",
            "--near-duplicate-min-tokens", "6",
            "--max-near-duplicate-representatives-per-bucket", "64",
            "--max-debug-control-repeats-per-session", "3",
            "--max-debug-task-burst-per-session", "9",
            "--debug-burst-window-minutes", "15",
            "--max-dedupe-seen-hashes", "100",
            "--max-dedupe-user-session-windows", "20",
            "--max-near-duplicate-buckets", "30",
        ])
        self.assertTrue(args.disable_episodes)
        self.assertEqual(args.selection_mode, "spool")
        self.assertEqual(args.max_in_memory_samples, 0)
        self.assertTrue(args.enable_route_labeler)
        self.assertTrue(args.enable_quality_labeler)
        self.assertTrue(args.enable_label_snippets)
        self.assertTrue(args.disable_dedupe)
        self.assertTrue(args.disable_near_duplicate_dedupe)
        self.assertTrue(args.disable_debug_noise_filter)
        self.assertEqual(args.near_duplicate_simhash_hamming, 5)
        self.assertEqual(args.near_duplicate_jaccard, 0.9)
        self.assertEqual(args.near_duplicate_min_chars, 32)
        self.assertEqual(args.near_duplicate_min_tokens, 6)
        self.assertEqual(args.max_near_duplicate_representatives_per_bucket, 64)
        self.assertEqual(args.max_debug_control_repeats_per_session, 3)
        self.assertEqual(args.max_debug_task_burst_per_session, 9)
        self.assertEqual(args.debug_burst_window_minutes, 15)
        self.assertEqual(args.max_dedupe_seen_hashes, 100)
        self.assertEqual(args.max_dedupe_user_session_windows, 20)
        self.assertEqual(args.max_near_duplicate_buckets, 30)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                pipeline.parse_args(["--date", "2026-07-15", "--compat-output-set", "--enable-quality-labeler"])
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                pipeline.parse_args(["--date", "2026-07-15", "--near-duplicate-jaccard", "1.1"])
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                pipeline.parse_args(["--date", "2026-07-15", "--near-duplicate-simhash-hamming", "65"])

    def test_route_label_payload_is_feature_only_by_default(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        payload, reason = pipeline.build_route_label_payload(canonical, allow_snippets=False)
        dumped = json.dumps(payload, ensure_ascii=False)
        self.assertIsNone(reason)
        self.assertEqual(payload["task"], "classify_route")
        self.assertNotIn("input", dumped)
        self.assertNotIn("messages", dumped)
        self.assertNotIn("sample_id", dumped)
        self.assertNotIn("request-1", dumped)
        self.assertNotIn("tenant", dumped)
        self.assertNotIn("13800138000", dumped)
        self.assertIn("features", payload["sample"])

    def test_leakage_scan_rejects_urls_paths_and_long_literals(self):
        pipeline = load_pipeline_module()
        rejected = [
            "see https://example.com/a",
            "open /var/log/private/app.log",
            "token abcdef1234567890abcdef1234567890abcdef12",
            "```python\nprint('secret')\n```",
            "<EMAIL_1>",
        ]
        for text in rejected:
            with self.subTest(text=text):
                ok, reason = pipeline.leakage_scan_text(text, max_chars=200)
                self.assertFalse(ok)
                self.assertTrue(reason)
        ok, reason = pipeline.leakage_scan_text("请总结这个订单问题", max_chars=200)
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_process_date_writes_selected_quality_episode_reports_without_forbidden_fields(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            first = sample_success_record()
            first["request_body"]["messages"] = [{"role": "user", "content": "请写一段 Python 代码，打印 hello"}]
            second = sample_success_record()
            second["request_id"] = "request-2"
            second["timestamp"] = "2026-07-15T00:05:00+08:00"
            second["request_body"]["messages"] = [
                {"role": "user", "content": "继续上面的 Python 代码，增加参数校验"}
            ]
            second["response_body"]["choices"][0]["message"]["content"] = "可以增加 if not name: raise ValueError('name')"
            write_json(day / "u" / "s" / "001.json", first)
            write_json(day / "u" / "s" / "002.json", second)
            write_index(day, [
                {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
                {"request_id": "request-2", "file_path": "2026-07-15/u/s/002.json"},
            ])

            result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

            self.assertEqual(result["accepted"], 2)
            selected_sft = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            selected_router = read_jsonl(output_root / "selected" / "router_classification" / "2026-07-15.jsonl")
            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            episodes = read_jsonl(output_root / "episodes" / "2026-07-15.jsonl")
            manifest = json.loads((output_root / "reports" / "2026-07-15.selection_manifest.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(selected_sft), 1)
            self.assertEqual(len(selected_router), 2)
            self.assertEqual(len(quality), 2)
            self.assertEqual(len(episodes), 1)
            self.assertIn("selected/sft", manifest["output_matrix"]["enabled_outputs"])
            for record in selected_sft + selected_router:
                self.assert_no_forbidden_selected_fields(record)
                self.assertEqual(record["schema_version"], pipeline.SELECTED_SCHEMA_VERSION)
            self.assertIn("schema_versions", manifest)

    def test_low_value_greetings_are_filtered_from_selected_not_legacy(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            raw = sample_success_record()
            raw["request_body"]["messages"] = [{"role": "user", "content": "你好"}]
            raw["response_body"]["choices"][0]["message"]["content"] = "你好"
            write_json(day / "u" / "s" / "001.json", raw)
            write_index(day, [{"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}])

            pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

            legacy_sft = read_jsonl(output_root / "sft" / "2026-07-15.jsonl")
            selected_sft = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertEqual(len(legacy_sft), 1)
            self.assertEqual(selected_sft, [])
            self.assertIn("greeting_or_probe", quality[0]["reject_reasons"])

    def test_selected_tool_use_requires_json_object_arguments(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["tools"] = [
            {"type": "function", "function": {"name": "search", "parameters": {"type": "object"}}}
        ]
        raw["response_body"]["choices"][0]["finish_reason"] = "tool_calls"
        raw["response_body"]["choices"][0]["message"] = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "search", "arguments": "[]"}}
            ],
        }
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        annotated = pipeline.annotate_task_and_quality(canonical, pipeline.default_selection_config())
        self.assertIsNone(pipeline.export_selected_tool_use_sft(annotated))
        self.assertIn("invalid_selected_tool_trace", annotated["quality"]["reject_reasons"])

    def test_disable_selection_keeps_legacy_outputs_only(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            write_json(day / "u" / "s" / "001.json", sample_success_record())
            write_index(day, [{"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}])

            result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15", disable_selection=True)

            self.assertEqual(result["accepted"], 1)
            self.assertTrue((output_root / "sft" / "2026-07-15.jsonl").exists())
            self.assertFalse((output_root / "selected" / "sft" / "2026-07-15.jsonl").exists())
            self.assertFalse((output_root / "quality" / "2026-07-15.jsonl").exists())
            self.assertFalse((output_root / "episodes" / "2026-07-15.jsonl").exists())

    def test_auto_selection_spools_and_cleans_temp_on_dry_run(self):
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
                dry_run=True,
                max_in_memory_samples=0,
                selection_mode="auto",
            )

            self.assertEqual(result["selection"]["mode_used"], "spool")
            self.assertFalse((output_root / ".tmp").exists())
            self.assertFalse((output_root / "selected" / "sft" / "2026-07-15.jsonl").exists())

    def test_active_lock_prevents_concurrent_runs(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            write_json(day / "u" / "s" / "001.json", sample_success_record())
            write_index(day, [{"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}])
            locks = output_root / ".tmp" / "locks"
            locks.mkdir(parents=True)
            (locks / "2026-07-15.lock").write_text(
                json.dumps({"pid": os.getpid(), "run_id": "active", "started_at": "2026-07-15T00:00:00Z"}),
                encoding="utf-8",
            )

            with self.assertRaises(RuntimeError):
                pipeline.process_date(str(input_root), str(output_root), "2026-07-15")


class SelectionDedupeTest(unittest.TestCase):
    def write_process_records(self, day, rows):
        index_rows = []
        for index, row in enumerate(rows):
            raw = sample_success_record()
            request_id = row.get("request_id", "request-%d" % index)
            raw["request_id"] = request_id
            raw["user_id"] = row.get("user_id", raw["user_id"])
            raw["tenant_id"] = row.get("tenant_id", raw["tenant_id"])
            raw["session_id"] = row.get("session_id", raw["session_id"])
            raw["timestamp"] = row.get("timestamp", raw["timestamp"])
            if "timestamp_ms" in row:
                raw["timestamp_ms"] = row["timestamp_ms"]
            raw["request_body"]["messages"] = [{"role": "user", "content": row["prompt"]}]
            raw["response_body"]["choices"][0]["message"]["content"] = row.get(
                "response",
                "可以使用 print('hello')",
            )
            name = "%03d.json" % index
            write_json(day / "u" / "s" / name, raw)
            index_rows.append({
                "request_id": request_id,
                "file_path": "2026-07-15/u/s/%s" % name,
            })
        write_index(day, index_rows)

    def make_annotated_record(
        self,
        pipeline,
        prompt,
        request_id="request-1",
        response="可以用 Python 逐行读取并统计结果。",
        timestamp_ms=None,
        user_id="user-1",
        tenant_id="tenant-1",
        session_id="session-1",
        config=None,
    ):
        raw = sample_success_record()
        raw["request_id"] = request_id
        raw["user_id"] = user_id
        raw["tenant_id"] = tenant_id
        raw["session_id"] = session_id
        if timestamp_ms is not None:
            raw["timestamp_ms"] = timestamp_ms
        raw["request_body"]["messages"] = [{"role": "user", "content": prompt}]
        raw["response_body"]["choices"][0]["message"]["content"] = response
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": request_id, "file_path": "2026-07-15/u/s/%s.json" % request_id},
            raw,
        )
        self.assertIsNone(reject)
        return pipeline.annotate_task_and_quality(canonical, config or pipeline.default_selection_config())

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

    def test_simhash_empty_tokens_returns_zero(self):
        pipeline = load_pipeline_module()
        self.assertEqual(pipeline.simhash64([]), 0)

    def test_normalize_for_dedupe_treats_embedded_placeholder_urls_as_urls(self):
        pipeline = load_pipeline_module()
        normalized = pipeline.normalize_for_dedupe("见 https://example.com/<SECRET_1>?n=42")
        self.assertEqual(normalized, "见 <url>")

    def test_normalize_for_dedupe_treats_placeholder_path_segments_as_paths(self):
        pipeline = load_pipeline_module()
        normalized = pipeline.normalize_for_dedupe("打开 src/<SECRET_1>/app.py 和 foo/<PHONE_1>/bar.py")
        self.assertEqual(normalized, "打开 <path> 和 <path>")

    def test_normalize_for_dedupe_does_not_treat_ordinary_slash_phrases_as_paths(self):
        pipeline = load_pipeline_module()
        self.assertEqual(
            pipeline.normalize_for_dedupe("请比较中文/英文句子的差异"),
            "请比较中文 英文句子的差异",
        )
        self.assertEqual(
            pipeline.normalize_for_dedupe("今天/明天都可以处理"),
            "今天 明天都可以处理",
        )
        self.assertEqual(
            pipeline.normalize_for_dedupe("please compare Chinese/English sentences"),
            "please compare chinese english sentences",
        )

    def test_init_dedupe_state_uses_bounded_collections(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(max_dedupe_seen_hashes=3)
        state = pipeline.init_dedupe_state(config)
        self.assertEqual(state["max_seen_hashes"], 3)
        self.assertIn("router_classification", state["seen"])
        self.assertEqual(state["dedupe_counts"], {})
        self.assertEqual(state["risk_counts"], {})

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

    def test_disable_dedupe_keeps_new_dedupe_rejects_off_but_selected_seen_guard_remains(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            self.write_process_records(day, [
                {
                    "request_id": "request-0",
                    "prompt": "请写 Python 代码打印 hello",
                    "response": "print('hello')",
                },
                {
                    "request_id": "request-1",
                    "prompt": "请写 Python 代码打印 hello",
                    "response": "print('hello')",
                },
            ])

            result = pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                disable_dedupe=True,
                k_threshold=1,
            )

            selected_sft = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            selection_manifest = json.loads(
                (output_root / "reports" / "2026-07-15.selection_manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            dedupe_reject_reasons = {
                "duplicate_content",
                "normalized_duplicate_content",
                "near_duplicate_content",
                "debug_noise_repeat",
                "debug_burst",
            }
            quality_reject_reasons = {
                reason
                for row in quality
                for reason in row["reject_reasons"]
            }

            self.assertEqual(len(selected_sft), 1)
            self.assertFalse(quality_reject_reasons & dedupe_reject_reasons)
            self.assertFalse(result["selection"]["dedupe_enabled"])
            self.assertFalse(selection_manifest["selection"]["dedupe_enabled"])

    def test_dedupe_rejected_counts_records_not_reasons(self):
        pipeline = load_pipeline_module()
        state = pipeline.init_selection_report_state()
        canonical = {
            "task": {
                "route_label": "code_generation",
                "intent_label": "write_code",
            },
            "quality": {
                "score_bucket": "high",
                "reject_reasons": ["near_duplicate_content", "debug_burst"],
                "risk_labels": ["near_duplicate", "debug_burst"],
            },
        }

        pipeline.update_selection_report_state(state, canonical)

        stats = pipeline.quality_stats_from_state(state, 1)
        self.assertEqual(stats["dedupe"]["near_duplicate_content"], 1)
        self.assertEqual(stats["dedupe"]["debug_burst"], 1)
        self.assertEqual(pipeline.dedupe_rejected_from_report_state(state), 1)

    def test_quality_stats_include_risk_labels_and_dedupe_summary(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            self.write_process_records(day, [
                {
                    "request_id": "request-0",
                    "prompt": "请写 Python 代码打印 hello",
                    "response": "print('hello')",
                },
                {
                    "request_id": "request-1",
                    "prompt": "请写 Python 代码打印 hello",
                    "response": "print('hello')",
                },
            ])

            pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                k_threshold=1,
            )

            stats = json.loads(
                (output_root / "reports" / "2026-07-15.quality_stats.json").read_text(encoding="utf-8")
            )
            self.assertIn("risk_labels", stats)
            self.assertIn("dedupe", stats)
            self.assertEqual(stats["dedupe"]["duplicate_content"], 1)
            self.assertGreaterEqual(stats["risk_labels"]["duplicate"], 1)

    def test_in_memory_episode_diagnostics_reflect_selected_duplicate_rejects(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            self.write_process_records(day, [
                {
                    "request_id": "request-0",
                    "prompt": "请写 Python 代码打印 hello",
                    "response": "print('hello')",
                    "timestamp_ms": 0,
                },
                {
                    "request_id": "request-1",
                    "prompt": "请写 Python 代码打印 hello",
                    "response": "print('hello')",
                    "timestamp_ms": 5 * 60 * 1000,
                },
            ])

            pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                k_threshold=1,
            )

            episodes = read_jsonl(output_root / "episodes" / "2026-07-15.jsonl")
            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertTrue(any("duplicate_content" in row["reject_reasons"] for row in quality))
            self.assertFalse(any(episode["eligible_for_selected_multi_turn"] for episode in episodes))

    def test_quality_dedupe_metadata_exports_only_safe_whitelisted_fields(self):
        pipeline = load_pipeline_module()
        canonical = {
            "sample_id": "sample-1",
            "source": {"date": "2026-07-15"},
            "request": {"model": "glm-5.2", "tools": []},
            "response": {"message": {"content": "", "tool_calls": []}},
            "task": {"route_label": "code_generation", "intent_label": "write_code"},
            "quality": {
                "dedupe": {
                    "bucket": "code_generation:write_code",
                    "normalized_prompt_hash": "abc123",
                    "simhash64": "0000000000000001",
                    "token_count": 7,
                    "decision": "rejected",
                    "matched_reason": "near_duplicate_content",
                    "matched_reasons": ["near_duplicate_content", 42, {"bad": "shape"}],
                    "suppressed_use_for": ["sft", ["nested"]],
                    "normalized_prompt": "RAW_PROMPT",
                    "request_id": "request-secret",
                    "raw_text": "secret",
                    "future_nested": {"raw": "secret"},
                },
            },
        }

        record = pipeline.quality_export_record(canonical)

        dedupe = record["quality"]["dedupe"]
        self.assertEqual(
            set(dedupe.keys()),
            set([
                "bucket",
                "normalized_prompt_hash",
                "simhash64",
                "token_count",
                "decision",
                "matched_reason",
                "matched_reasons",
                "suppressed_use_for",
            ]),
        )
        self.assertEqual(dedupe["matched_reasons"], ["near_duplicate_content"])
        self.assertEqual(dedupe["suppressed_use_for"], ["sft"])
        dumped = json.dumps(record, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("RAW_PROMPT", dumped)
        self.assertNotIn("request-secret", dumped)
        self.assertNotIn("secret", dumped)
        self.assertNotIn("future_nested", dumped)

    def test_quality_output_includes_safe_dedupe_metadata_without_raw_text(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            prompt = "请写 Python 代码打印 SAFE_DEDUPE_PROMPT_FRAGMENT"
            self.write_process_records(day, [
                {
                    "request_id": "request-safe-dedupe",
                    "prompt": prompt,
                    "response": "print('safe dedupe')",
                },
            ])

            pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertEqual(len(quality), 1)
            dedupe = quality[0]["quality"].get("dedupe")
            self.assertIsInstance(dedupe, dict)
            for key in ["normalized_prompt_hash", "simhash64", "bucket", "token_count", "decision"]:
                self.assertIn(key, dedupe)
            dumped = json.dumps(quality[0], ensure_ascii=False, sort_keys=True)
            self.assertNotIn("SAFE_DEDUPE_PROMPT_FRAGMENT", dumped)
            self.assertNotIn("request-safe-dedupe", dumped)

    def test_spool_mode_applies_dedupe_before_quality_and_selected_outputs(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            self.write_process_records(day, [
                {
                    "request_id": "request-0",
                    "prompt": "请写 Python 代码打印 hello",
                    "response": "print('hello')",
                },
                {
                    "request_id": "request-1",
                    "prompt": "请写 Python 代码打印 hello",
                    "response": "print('hello')",
                },
            ])

            result = pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                selection_mode="spool",
                k_threshold=1,
            )

            self.assertEqual(result["selection"]["mode_used"], "spool")
            selected_sft = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertEqual(len(selected_sft), 1)
            self.assertTrue(any("duplicate_content" in row["reject_reasons"] for row in quality))

    def test_sort_spool_jsonl_by_key_flushes_chunks_on_byte_budget(self):
        pipeline = load_pipeline_module()
        original_writer = pipeline.write_sorted_spool_chunk
        chunks = []

        def recording_writer(records, key_fn, spool_path, label):
            chunks.append({
                "count": len(records),
                "bytes": sum(pipeline.estimate_record_size(record) for record in records),
            })
            return original_writer(records, key_fn, spool_path, label)

        try:
            pipeline.write_sorted_spool_chunk = recording_writer
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                spool_path = root / "candidates.jsonl"
                records = [
                    {"sort": 3, "payload": "x" * 2048},
                    {"sort": 2, "payload": "y" * 2048},
                    {"sort": 1, "payload": "z" * 2048},
                ]
                with spool_path.open("w", encoding="utf-8") as handle:
                    for record in records:
                        pipeline.write_jsonl_record(handle, record)
                config = pipeline.default_selection_config(
                    max_in_memory_samples=100,
                    max_selection_memory_mb=0,
                )

                sorted_path = pipeline.sort_spool_jsonl_by_key(
                    spool_path,
                    lambda record: record["sort"],
                    config,
                    "byte_budget",
                )

                self.assertEqual([row["sort"] for row in read_jsonl(sorted_path)], [1, 2, 3])
                self.assertGreater(len(chunks), 1)
                self.assertTrue(all(chunk["count"] == 1 for chunk in chunks))
        finally:
            pipeline.write_sorted_spool_chunk = original_writer

    def test_write_sorted_spool_chunk_removes_partial_file_on_failure(self):
        pipeline = load_pipeline_module()
        original_write_jsonl_record = pipeline.write_jsonl_record

        def failing_write_jsonl_record(handle, record):
            handle.write("partial")
            raise RuntimeError("chunk write failed")

        try:
            pipeline.write_jsonl_record = failing_write_jsonl_record
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                spool_path = root / "candidates.jsonl"
                spool_path.write_text('{"original": true}\n', encoding="utf-8")

                with self.assertRaises(RuntimeError):
                    pipeline.write_sorted_spool_chunk(
                        [{"sort": 1}],
                        lambda record: record["sort"],
                        spool_path,
                        "event_order.chunk",
                    )

                self.assertEqual([path.name for path in root.iterdir()], ["candidates.jsonl"])
        finally:
            pipeline.write_jsonl_record = original_write_jsonl_record

    def test_merge_sorted_spool_chunks_removes_partial_output_on_failure(self):
        pipeline = load_pipeline_module()
        original_write_jsonl_record = pipeline.write_jsonl_record

        def failing_write_jsonl_record(handle, record):
            handle.write("partial")
            raise RuntimeError("merge write failed")

        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                chunk_a = root / "chunk-a.jsonl"
                chunk_b = root / "chunk-b.jsonl"
                output_path = root / "candidates.jsonl.event_order.merge0_0.failure.jsonl"
                with chunk_a.open("w", encoding="utf-8") as handle:
                    original_write_jsonl_record(handle, {"sort": 1})
                with chunk_b.open("w", encoding="utf-8") as handle:
                    original_write_jsonl_record(handle, {"sort": 2})

                pipeline.write_jsonl_record = failing_write_jsonl_record
                with self.assertRaises(RuntimeError):
                    pipeline.merge_sorted_spool_chunks(
                        [chunk_a, chunk_b],
                        lambda record: record["sort"],
                        output_path,
                    )

                self.assertTrue(chunk_a.exists())
                self.assertTrue(chunk_b.exists())
                self.assertFalse(output_path.exists())
        finally:
            pipeline.write_jsonl_record = original_write_jsonl_record

    def test_spooled_selection_skips_episode_sort_without_diagnostic_handles(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(k_threshold=1)
        original_sort = pipeline.sort_spool_jsonl_by_key
        labels = []

        def recording_sort(source_path, key_fn, config_arg, label, *args, **kwargs):
            labels.append(label)
            return original_sort(source_path, key_fn, config_arg, label, *args, **kwargs)

        try:
            pipeline.sort_spool_jsonl_by_key = recording_sort
            with tempfile.TemporaryDirectory() as tmp:
                spool_path = pathlib.Path(tmp) / "candidates.jsonl"
                record = self.make_annotated_record(
                    pipeline,
                    "请写 Python 代码打印 spool",
                    request_id="request-spool",
                    response="print('spool')",
                    timestamp_ms=1000,
                    config=config,
                )
                with spool_path.open("w", encoding="utf-8") as handle:
                    pipeline.write_jsonl_record(handle, record)

                result = pipeline.process_spooled_selection_records(
                    spool_path,
                    config,
                    "2026-07-15",
                    handles=None,
                )

                self.assertEqual(len(result["selected_outputs"]["sft"]), 1)
                self.assertNotIn("episode_order", labels)
        finally:
            pipeline.sort_spool_jsonl_by_key = original_sort

    def test_spool_normalized_duplicate_keeps_same_ranked_winner_as_in_memory(self):
        pipeline = load_pipeline_module()
        original_load_label_config = pipeline.load_label_config
        original_call_label_model = pipeline.call_label_model

        def fake_load_label_config():
            return {"enabled": True, "max_input_chars": 1200}

        def fake_call_label_model(payload, label_config, parser=pipeline.parse_quality_label_response):
            prompt = payload.get("sample", {}).get("user_snippet", "")
            score = 0.65 if "42" in prompt else 0.95
            return {
                "quality_score": score,
                "value_labels": [],
                "risk_labels": [],
                "reason": "test_score",
            }, None

        try:
            pipeline.load_label_config = fake_load_label_config
            pipeline.call_label_model = fake_call_label_model
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                input_root = root / "audit"
                day = input_root / "2026-07-15"
                low_prompt = "请修复第 42 行 Python 报错"
                high_prompt = "请修复第 43 行 Python 报错"
                self.write_process_records(day, [
                    {
                        "request_id": "request-low",
                        "prompt": low_prompt,
                        "response": "可以检查异常栈并修复参数。",
                        "timestamp_ms": 1000,
                    },
                    {
                        "request_id": "request-high",
                        "prompt": high_prompt,
                        "response": "可以检查异常栈并修复参数。",
                        "timestamp_ms": 2000,
                    },
                ])

                for mode in ["in-memory", "spool"]:
                    pipeline.process_date(
                        str(input_root),
                        str(root / ("out-" + mode)),
                        "2026-07-15",
                        selection_mode=mode,
                        enable_quality_labeler=True,
                        enable_label_snippets=True,
                        k_threshold=1,
                    )

                in_memory_selected = read_jsonl(
                    root / "out-in-memory" / "selected" / "sft" / "2026-07-15.jsonl"
                )
                spool_selected = read_jsonl(
                    root / "out-spool" / "selected" / "sft" / "2026-07-15.jsonl"
                )
                in_memory_quality = read_jsonl(root / "out-in-memory" / "quality" / "2026-07-15.jsonl")
                spool_quality = read_jsonl(root / "out-spool" / "quality" / "2026-07-15.jsonl")

                self.assertEqual(len(in_memory_selected), 1)
                self.assertEqual(len(spool_selected), 1)
                self.assertEqual(in_memory_selected[0]["input"], high_prompt)
                self.assertEqual(spool_selected[0]["input"], high_prompt)
                self.assertTrue(
                    any(
                        row["quality"]["final_quality_score"] == 0.65
                        and "normalized_duplicate_content" in row["reject_reasons"]
                        for row in in_memory_quality
                    )
                )
                self.assertTrue(
                    any(
                        row["quality"]["final_quality_score"] == 0.65
                        and "normalized_duplicate_content" in row["reject_reasons"]
                        for row in spool_quality
                    )
                )
        finally:
            pipeline.load_label_config = original_load_label_config
            pipeline.call_label_model = original_call_label_model

    def test_spool_near_duplicate_ignores_non_selected_representatives(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(k_threshold=1, selected_min_score=0.85)
        records = [
            self.make_annotated_record(
                pipeline,
                "请帮我写一个 Python 脚本读取 jsonl 文件并统计每个用户的调用次数",
                request_id="request-low",
                response="可以用 json 模块逐行读取并累计用户调用次数。",
                timestamp_ms=1000,
                config=config,
            ),
            self.make_annotated_record(
                pipeline,
                "帮我写 Python 脚本读取 jsonl 并统计每个用户调用次数",
                request_id="request-high",
                response="可以用 json 模块逐行读取并累计用户调用次数。",
                timestamp_ms=2000,
                config=config,
            ),
        ]
        records[0]["quality"]["deterministic_quality_score"] = 0.8
        records[0]["quality"]["final_quality_score"] = 0.8
        records[0]["quality"]["score_bucket"] = "high"
        records[0]["quality"]["use_for"] = []
        records[1]["quality"]["deterministic_quality_score"] = 0.88
        records[1]["quality"]["final_quality_score"] = 0.88
        records[1]["quality"]["score_bucket"] = "high"
        with tempfile.TemporaryDirectory() as tmp:
            spool_path = pathlib.Path(tmp) / "candidates.jsonl"
            with spool_path.open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n")

            result = pipeline.process_spooled_selection_records(spool_path, config, "2026-07-15")

        self.assertEqual(len(result["selected_outputs"]["sft"]), 1)
        self.assertNotIn("near_duplicate_content", result["quality_stats"]["dedupe"])

    def test_selection_manifest_records_dedupe_config(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            self.write_process_records(day, [
                {
                    "request_id": "request-0",
                    "prompt": "请写 Python 代码打印 manifest",
                    "response": "print('manifest')",
                },
            ])

            result = pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                near_duplicate_simhash_hamming=5,
            )

            selection_manifest = json.loads(
                (output_root / "reports" / "2026-07-15.selection_manifest.json").read_text(encoding="utf-8")
            )
            self.assertTrue(result["selection"]["dedupe_enabled"])
            self.assertEqual(result["selection"]["dedupe_config"]["near_duplicate_simhash_hamming"], 5)
            self.assertTrue(selection_manifest["selection"]["dedupe_enabled"])
            self.assertEqual(
                selection_manifest["selection"]["dedupe_config"]["near_duplicate_simhash_hamming"],
                5,
            )

    def test_router_duplicate_does_not_filter_distinct_sft_response(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            for index, response in enumerate(["print('hello one')", "print('hello two')"]):
                raw = sample_success_record()
                raw["request_id"] = "request-%d" % index
                raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 代码打印 hello"}]
                raw["response_body"]["choices"][0]["message"]["content"] = response
                write_json(day / "u" / "s" / ("%03d.json" % index), raw)
            write_index(day, [
                {"request_id": "request-0", "file_path": "2026-07-15/u/s/000.json"},
                {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            ])

            pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

            selected_router = read_jsonl(output_root / "selected" / "router_classification" / "2026-07-15.jsonl")
            selected_sft = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertEqual(len(selected_router), 1)
            self.assertEqual(len(selected_sft), 2)
            self.assertFalse(any("duplicate_content" in row["reject_reasons"] for row in quality))
            self.assertTrue(any("duplicate" in row["quality"]["risk_labels"] for row in quality))

    def test_apply_dedupe_annotation_does_not_write_selected_duplicate_state(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(router_min_score=1.0)
        state = pipeline.init_dedupe_state(config)
        records = []
        for index, prompt in enumerate(["请修复第 42 行 Python 报错", "请修复第 43 行 Python 报错"]):
            raw = sample_success_record()
            raw["request_id"] = "request-%d" % index
            raw["request_body"]["messages"] = [{"role": "user", "content": prompt}]
            raw["response_body"]["choices"][0]["message"]["content"] = "可以检查异常栈并修复参数。"
            canonical, reject = pipeline.build_canonical_sample(
                "2026-07-15",
                {"request_id": raw["request_id"], "file_path": "2026-07-15/u/s/%03d.json" % index},
                raw,
            )
            self.assertIsNone(reject)
            records.append(pipeline.annotate_task_and_quality(canonical, config))

        pipeline.apply_dedupe_annotation(records[0], config, state)
        pipeline.apply_dedupe_annotation(records[1], config, state)

        self.assertEqual(state["seen"]["sft"], set())
        self.assertEqual(state["normalized"]["sft"], set())
        self.assertNotIn("normalized_duplicate_content", records[1]["quality"]["reject_reasons"])
        self.assertIn("dedupe", records[1]["quality"])

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

            pipeline.process_date(str(input_root), str(output_root), "2026-07-15", router_min_score=1.0)

            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            selected = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            self.assertEqual(len(selected), 1)
            self.assertTrue(any("normalized_duplicate_content" in row["reject_reasons"] for row in quality))

    def test_near_duplicate_prompt_in_same_bucket_is_filtered(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(router_min_score=1.0)
        prompts = [
            "请帮我写一个 Python 脚本读取 jsonl 文件并统计每个用户的调用次数",
            "帮我写 Python 脚本读取 jsonl 并统计每个用户调用次数",
        ]
        records = [
            self.make_annotated_record(
                pipeline,
                prompt,
                request_id="request-%d" % index,
                timestamp_ms=1000 + index,
                config=config,
            )
            for index, prompt in enumerate(prompts)
        ]

        pipeline.apply_dedupe_annotations_to_records(records, config)
        selected = pipeline.build_selected_outputs(records, [], config)

        self.assertEqual(len(selected["sft"]), 1)
        self.assertNotIn("near_duplicate_content", records[0]["quality"]["reject_reasons"])
        self.assertIn("near_duplicate_content", records[1]["quality"]["reject_reasons"])
        self.assertIn("near_duplicate", records[1]["quality"]["risk_labels"])
        self.assertEqual(records[1]["quality"]["use_for"], [])

    def test_near_duplicate_with_hmac_selection_key_uses_coarse_bucket(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(
            router_min_score=1.0,
            selection_hmac_key="secret-key",
        )
        prompts = [
            "请帮我写一个 Python 脚本读取 jsonl 文件并统计每个用户的调用次数",
            "帮我写 Python 脚本读取 jsonl 并统计每个用户调用次数",
        ]
        records = [
            self.make_annotated_record(
                pipeline,
                prompt,
                request_id="request-hmac-%d" % index,
                timestamp_ms=1000 + index,
                config=config,
            )
            for index, prompt in enumerate(prompts)
        ]

        pipeline.apply_dedupe_annotations_to_records(records, config)

        self.assertIn("near_duplicate_content", records[1]["quality"]["reject_reasons"])
        self.assertIn("near_duplicate", records[1]["quality"]["risk_labels"])

    def test_similar_prompt_in_different_route_bucket_is_not_near_duplicate(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(router_min_score=1.0)
        records = [
            self.make_annotated_record(
                pipeline,
                "请帮我写一个 Python 脚本读取 jsonl 文件并统计每个用户的调用次数",
                request_id="request-0",
                timestamp_ms=1000,
                config=config,
            ),
            self.make_annotated_record(
                pipeline,
                "帮我写 Python 脚本读取 jsonl 并统计每个用户调用次数",
                request_id="request-1",
                timestamp_ms=1001,
                config=config,
            ),
        ]
        records[1]["task"]["route_label"] = "domain_qa"
        records[1]["task"]["intent_label"] = "domain_lookup"
        records[1]["task"]["task_bucket"] = "domain_qa:domain_lookup"

        state = pipeline.init_dedupe_state(config)
        pipeline.apply_dedupe_annotation(records[0], config, state)
        pipeline.apply_dedupe_annotation(records[1], config, state)

        self.assertNotIn("near_duplicate_content", records[1]["quality"]["reject_reasons"])
        self.assertNotIn("near_duplicate", records[1]["quality"]["risk_labels"])
        self.assertIn("sft", records[1]["quality"]["use_for"])

    def test_sequence_like_keyword_substitution_is_not_near_duplicate(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(router_min_score=1.0)
        records = [
            self.make_annotated_record(
                pipeline,
                "请写 Python 脚本同步执行任务队列并返回处理结果",
                request_id="request-sync",
                response="可以使用同步循环逐个执行任务并收集结果。",
                timestamp_ms=1000,
                config=config,
            ),
            self.make_annotated_record(
                pipeline,
                "请写 Python 脚本异步执行任务队列并返回处理结果",
                request_id="request-async",
                response="可以使用 asyncio 并发调度任务并汇总结果。",
                timestamp_ms=1001,
                config=config,
            ),
        ]

        pipeline.apply_dedupe_annotations_to_records(records, config)

        self.assertNotIn("near_duplicate_content", records[1]["quality"]["reject_reasons"])
        self.assertNotIn("near_duplicate", records[1]["quality"]["risk_labels"])
        self.assertIn("sft", records[1]["quality"]["use_for"])

    def test_repeated_control_turns_trigger_debug_noise_repeat(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(
            selected_min_score=0.0,
            router_min_score=0.0,
            sft_min_score=0.0,
            max_debug_control_repeats_per_session=2,
        )
        records = [
            self.make_annotated_record(
                pipeline,
                "继续",
                request_id="request-%d" % index,
                response="继续处理上一个问题。",
                timestamp_ms=1000 + index,
                config=config,
            )
            for index in range(3)
        ]

        pipeline.apply_dedupe_annotations_to_records(records, config)

        self.assertNotIn("debug_noise_repeat", records[0]["quality"]["reject_reasons"])
        self.assertNotIn("debug_noise_repeat", records[1]["quality"]["reject_reasons"])
        self.assertIn("debug_noise_repeat", records[2]["quality"]["reject_reasons"])
        self.assertIn("debug_noise", records[2]["quality"]["risk_labels"])
        self.assertEqual(records[2]["quality"]["use_for"], [])

    def test_debug_burst_is_order_independent_from_selection_rank(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(
            enable_near_duplicate_dedupe=False,
            max_debug_task_burst_per_session=2,
            debug_burst_window_minutes=20,
            router_min_score=1.0,
        )
        minutes = [0, 10, 100, 15]
        records = [
            self.make_annotated_record(
                pipeline,
                "请写 Python 脚本读取 jsonl 文件并统计每个用户调用次数",
                request_id="request-%d" % minute,
                response="可以用 json 模块逐行读取并累计用户调用次数。%d" % minute,
                timestamp_ms=minute * 60 * 1000,
                config=config,
            )
            for minute in minutes
        ]
        for record in records[:3]:
            record["quality"]["final_quality_score"] = 0.95
        records[3]["quality"]["final_quality_score"] = 0.50

        pipeline.apply_dedupe_annotations_to_records(records, config)

        self.assertIn("debug_burst", records[3]["quality"]["reject_reasons"])
        self.assertIn("debug_burst", records[3]["quality"]["risk_labels"])

    def test_debug_burst_uses_true_window_not_symmetric_span(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(
            enable_near_duplicate_dedupe=False,
            max_debug_task_burst_per_session=2,
            debug_burst_window_minutes=20,
            router_min_score=1.0,
        )
        middle = self.make_annotated_record(
            pipeline,
            "请写 Python 脚本读取 jsonl 文件并统计每个用户调用次数",
            request_id="request-middle",
            response="可以用 json 模块逐行读取并累计用户调用次数。",
            timestamp_ms=20 * 60 * 1000,
            config=config,
        )
        state = pipeline.init_dedupe_state(config)
        burst_key = "%s:%s" % (
            pipeline.dedupe_session_key(middle),
            middle["task"]["task_fingerprint_internal"],
        )
        state["session_task_times"][burst_key] = [0, 40 * 60 * 1000]

        pipeline.apply_dedupe_annotation(middle, config, state)

        self.assertNotIn("debug_burst", middle["quality"]["reject_reasons"])
        self.assertNotIn("debug_burst", middle["quality"]["risk_labels"])

    def test_debug_burst_task_time_state_is_bounded_per_key(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(
            enable_near_duplicate_dedupe=False,
            max_debug_task_burst_per_session=2,
            debug_burst_window_minutes=20,
            router_min_score=1.0,
        )
        records = [
            self.make_annotated_record(
                pipeline,
                "请写 Python 脚本读取 jsonl 文件并统计每个用户调用次数",
                request_id="request-burst-%03d" % index,
                response="可以用 json 模块逐行读取并累计用户调用次数。%d" % index,
                timestamp_ms=index * 1000,
                config=config,
            )
            for index in range(100)
        ]

        state = pipeline.apply_dedupe_annotations_to_records(records, config)

        self.assertLessEqual(
            max(len(times) for times in state["session_task_times"].values()),
            config["max_debug_task_burst_per_session"] + 1,
        )

    def test_same_session_task_burst_triggers_debug_burst(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config(
            enable_near_duplicate_dedupe=False,
            max_debug_task_burst_per_session=2,
            debug_burst_window_minutes=20,
            router_min_score=1.0,
        )
        records = [
            self.make_annotated_record(
                pipeline,
                "请写 Python 脚本读取 jsonl 文件并统计每个用户调用次数",
                request_id="request-%d" % index,
                response="可以用 json 模块逐行读取并累计用户调用次数。%d" % index,
                timestamp_ms=1000 + index * 60000,
                config=config,
            )
            for index in range(4)
        ]

        pipeline.apply_dedupe_annotations_to_records(records, config)

        self.assertNotIn("debug_burst", records[0]["quality"]["reject_reasons"])
        self.assertNotIn("debug_burst", records[1]["quality"]["reject_reasons"])
        self.assertIn("debug_burst", records[2]["quality"]["reject_reasons"])
        self.assertIn("debug_burst", records[2]["quality"]["risk_labels"])
        self.assertEqual(records[2]["quality"]["use_for"], [])
        self.assertIn("debug_burst", records[3]["quality"]["reject_reasons"])

    def test_quota_skipped_duplicate_candidate_does_not_pollute_cross_user_selection(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            rows = [
                ("request-a-1", "user-a", "请写 Python 代码打印 quota seed", "print('quota seed')", "000.json"),
                ("request-a-2", "user-a", "请写 Python 代码打印 shared", "print('shared')", "001.json"),
                ("request-b-1", "user-b", "请写 Python 代码打印 shared", "print('shared')", "002.json"),
            ]
            index_rows = []
            for request_id, user_id, prompt, response, name in rows:
                raw = sample_success_record()
                raw["request_id"] = request_id
                raw["user_id"] = user_id
                raw["session_id"] = "session-" + user_id
                raw["request_body"]["messages"] = [{"role": "user", "content": prompt}]
                raw["response_body"]["choices"][0]["message"]["content"] = response
                path = day / user_id / "s" / name
                write_json(path, raw)
                index_rows.append({"request_id": request_id, "file_path": "2026-07-15/%s/s/%s" % (user_id, name)})
            write_index(day, index_rows)

            pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                max_selected_sft_per_user_per_day=1,
                router_min_score=1.0,
            )

            selected = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertEqual(len(selected), 2)
            self.assertEqual(
                sorted(row["output"] for row in selected),
                ["print('quota seed')", "print('shared')"],
            )
            self.assertFalse(any("duplicate_content" in row["reject_reasons"] for row in quality))
            self.assertFalse(any("normalized_duplicate_content" in row["reject_reasons"] for row in quality))
            self.assertFalse(any("duplicate" in row["quality"]["risk_labels"] for row in quality))


class SelectionHardeningTest(unittest.TestCase):
    def test_quality_model_high_score_cannot_rescue_hard_reject(self):
        pipeline = load_pipeline_module()
        old_env = os.environ.copy()
        original_urlopen = pipeline.urllib.request.urlopen

        class FakeResponse(object):
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return json.dumps({
                    "choices": [{"message": {"content": '{"quality_score":0.99,"value_labels":["code_task"],"risk_labels":[],"reason":"high"}'}}]
                }).encode("utf-8")

        try:
            os.environ.clear()
            os.environ.update(old_env)
            os.environ.update({
                "AUDIT_LABEL_BASE_URL": "https://example.test/v1",
                "AUDIT_LABEL_API_KEY": "key",
                "AUDIT_LABEL_MODEL": "label-model",
            })
            pipeline.urllib.request.urlopen = lambda request, timeout=None: FakeResponse()
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                input_root = root / "audit"
                output_root = root / "out"
                day = input_root / "2026-07-15"
                raw = sample_success_record()
                raw["request_body"]["messages"] = [{"role": "user", "content": "你好"}]
                raw["response_body"]["choices"][0]["message"]["content"] = "你好"
                write_json(day / "u" / "s" / "001.json", raw)
                write_index(day, [{"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}])

                pipeline.process_date(
                    str(input_root),
                    str(output_root),
                    "2026-07-15",
                    enable_quality_labeler=True,
                )

                selected = read_jsonl(output_root / "selected" / "router_classification" / "2026-07-15.jsonl")
                quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")[0]
                self.assertEqual(selected, [])
                self.assertEqual(quality["quality"]["deterministic_quality_score"], 0.2)
                self.assertEqual(quality["quality"]["final_quality_score"], 0.2)
                self.assertIn("greeting_or_probe", quality["reject_reasons"])
        finally:
            pipeline.urllib.request.urlopen = original_urlopen
            os.environ.clear()
            os.environ.update(old_env)

    def test_quality_model_risk_removes_selected_eligibility(self):
        pipeline = load_pipeline_module()
        old_env = os.environ.copy()
        original_urlopen = pipeline.urllib.request.urlopen

        class FakeResponse(object):
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return json.dumps({
                    "choices": [{"message": {"content": '{"quality_score":0.95,"value_labels":[],"risk_labels":["redaction_risk"],"reason":"risk"}'}}]
                }).encode("utf-8")

        try:
            os.environ.clear()
            os.environ.update(old_env)
            os.environ.update({
                "AUDIT_LABEL_BASE_URL": "https://example.test/v1",
                "AUDIT_LABEL_API_KEY": "key",
                "AUDIT_LABEL_MODEL": "label-model",
            })
            pipeline.urllib.request.urlopen = lambda request, timeout=None: FakeResponse()
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                input_root = root / "audit"
                output_root = root / "out"
                day = input_root / "2026-07-15"
                raw = sample_success_record()
                raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 代码打印 hello"}]
                write_json(day / "u" / "s" / "001.json", raw)
                write_index(day, [{"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}])

                pipeline.process_date(
                    str(input_root),
                    str(output_root),
                    "2026-07-15",
                    enable_quality_labeler=True,
                )

                selected = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
                quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")[0]
                self.assertEqual(selected, [])
                self.assertIn("model_risk", quality["reject_reasons"])
                self.assertIn("redaction_risk", quality["quality"]["risk_labels"])
        finally:
            pipeline.urllib.request.urlopen = original_urlopen
            os.environ.clear()
            os.environ.update(old_env)

    def test_episode_grouping_splits_gap_and_marks_missing_session_fallback(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config()
        first_raw = sample_success_record()
        second_raw = sample_success_record()
        second_raw["request_id"] = "request-2"
        second_raw["timestamp"] = "2026-07-15T00:45:00+08:00"
        third_raw = sample_success_record()
        third_raw["request_id"] = "request-3"
        third_raw["session_id"] = ""
        third_raw["timestamp"] = "2026-07-15T00:05:00+08:00"
        records = []
        for index, raw in enumerate([first_raw, second_raw, third_raw], 1):
            canonical, reject = pipeline.build_canonical_sample(
                "2026-07-15",
                {"request_id": raw["request_id"], "file_path": "2026-07-15/u/s/%03d.json" % index, "_index_line": index},
                raw,
            )
            self.assertIsNone(reject)
            records.append(pipeline.annotate_task_and_quality(canonical, config))
        episodes = pipeline.build_episodes(records, config)
        self.assertEqual([episode["turn_count"] for episode in episodes], [1, 1, 1])
        self.assertTrue(any(episode["missing_session_fallback"] for episode in episodes))
        self.assertFalse(any(episode["eligible_for_selected_multi_turn"] for episode in episodes))

    def test_selected_tool_trace_rejects_unknown_tool_and_malformed_arguments(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config()
        raw = sample_success_record()
        raw["request_body"]["tools"] = [
            {"type": "function", "function": {"name": "search", "parameters": {"type": "object"}}}
        ]
        raw["response_body"]["choices"][0]["finish_reason"] = "tool_calls"
        cases = [
            ("unknown", {"id": "call_1", "type": "function", "function": {"name": "missing", "arguments": "{}"}}),
            ("malformed", {"id": "call_1", "type": "function", "function": {"name": "search", "arguments": "{bad json}"}}),
            ("scalar", {"id": "call_1", "type": "function", "function": {"name": "search", "arguments": '"x"'}}),
        ]
        for name, tool_call in cases:
            with self.subTest(name=name):
                current = copy.deepcopy(raw)
                current["response_body"]["choices"][0]["message"] = {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [tool_call],
                }
                canonical, reject = pipeline.build_canonical_sample(
                    "2026-07-15",
                    {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
                    current,
                )
                self.assertIsNone(reject)
                annotated = pipeline.annotate_task_and_quality(canonical, config)
                self.assertIsNone(pipeline.export_selected_tool_use_sft(annotated))
                self.assertIn("invalid_selected_tool_trace", annotated["quality"]["reject_reasons"])

    def test_reject_reports_are_non_linkable(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            raw = sample_success_record()
            raw["status"] = "failed"
            write_json(day / "tenant-1" / "user-1" / "s" / "001.json", raw)
            write_index(day, [{"request_id": "request-1", "file_path": "2026-07-15/tenant-1/user-1/s/001.json"}])

            pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

            reject_text = (output_root / "reports" / "2026-07-15.rejects.jsonl").read_text(encoding="utf-8")
            reject = json.loads(reject_text)
            self.assertEqual(reject["reason"], "status_not_success")
            self.assertNotIn("request_id", reject_text)
            self.assertNotIn("file_path_hash", reject_text)
            self.assertNotIn("tenant-1", reject_text)

    def test_selected_min_score_is_global_gate(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            raw = sample_success_record()
            raw["request_body"]["messages"] = [{"role": "user", "content": "解释一下"}]
            raw["response_body"]["choices"][0]["message"]["content"] = "这是一个简短解释。"
            write_json(day / "u" / "s" / "001.json", raw)
            write_index(day, [{"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}])

            pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                selected_min_score=0.7,
                router_min_score=0.1,
            )

            selected = read_jsonl(output_root / "selected" / "router_classification" / "2026-07-15.jsonl")
            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")[0]
            self.assertEqual(selected, [])
            self.assertEqual(quality["quality"]["use_for"], [])

    def test_spool_mode_does_not_call_in_memory_selection_builders(self):
        pipeline = load_pipeline_module()
        original_build_episodes = pipeline.build_episodes
        try:
            def forbidden_build_episodes(records, config):
                raise AssertionError("spool mode must not route through in-memory episode builder")
            pipeline.build_episodes = forbidden_build_episodes
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                input_root = root / "audit"
                output_root = root / "out"
                day = input_root / "2026-07-15"
                for index in range(2):
                    raw = sample_success_record()
                    raw["request_id"] = "request-%d" % index
                    raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 代码 %d" % index}]
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

                self.assertEqual(result["selection"]["mode_used"], "spool")
                self.assertEqual(result["selection"]["candidate_count"], 2)
                self.assertFalse((output_root / ".tmp").exists())
        finally:
            pipeline.build_episodes = original_build_episodes

    def test_missing_event_time_records_do_not_merge_into_episode(self):
        pipeline = load_pipeline_module()
        config = pipeline.default_selection_config()
        records = []
        for index in range(2):
            raw = sample_success_record()
            raw.pop("timestamp", None)
            raw.pop("timestamp_ms", None)
            raw["request_id"] = "request-%d" % index
            canonical, reject = pipeline.build_canonical_sample(
                "2026-07-15",
                {"request_id": raw["request_id"], "file_path": "2026-07-15/u/s/%03d.json" % index, "_index_line": index},
                raw,
            )
            self.assertIsNone(reject)
            records.append(pipeline.annotate_task_and_quality(canonical, config))
        episodes = pipeline.build_episodes(records, config)
        self.assertEqual([episode["turn_count"] for episode in episodes], [1, 1])
        self.assertTrue(all(episode["index_order_only"] for episode in episodes))

    def test_label_payload_buckets_unknown_model_and_client_type(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["model"] = "tenant-secret-model-v1"
        raw["request_body"]["model"] = "tenant-secret-model-v1"
        raw["client_type"] = "tenant-secret-client"
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        payload, error = pipeline.build_route_label_payload(canonical, allow_snippets=False)
        self.assertIsNone(error)
        dumped = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("tenant-secret", dumped)
        self.assertEqual(payload["sample"]["features"]["model_bucket"], "other")
        self.assertEqual(payload["sample"]["features"]["client_type_bucket"], "other")

    def test_tool_result_must_follow_prior_assistant_tool_call(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["tools"] = [
            {"type": "function", "function": {"name": "search", "parameters": {"type": "object"}}}
        ]
        raw["request_body"]["messages"] = [
            {"role": "user", "content": "查一下"},
            {"role": "tool", "tool_call_id": "call_old", "content": "result before call"},
        ]
        raw["response_body"]["choices"][0]["finish_reason"] = "tool_calls"
        raw["response_body"]["choices"][0]["message"] = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "search", "arguments": "{}"}}
            ],
        }
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        annotated = pipeline.annotate_task_and_quality(canonical, pipeline.default_selection_config())
        self.assertIsNone(pipeline.export_selected_tool_use_sft(annotated))
        self.assertIn("invalid_selected_tool_trace", annotated["quality"]["reject_reasons"])

    def test_high_value_task_quota_limits_selected_sft_per_task(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            first = sample_success_record()
            second = sample_success_record()
            second["request_id"] = "request-2"
            for raw, response in [
                (first, "print('hello one')"),
                (second, "print('hello two')"),
            ]:
                raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 代码打印 hello"}]
                raw["response_body"]["choices"][0]["message"]["content"] = response
            write_json(day / "u" / "s" / "001.json", first)
            write_json(day / "u" / "s" / "002.json", second)
            write_index(day, [
                {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
                {"request_id": "request-2", "file_path": "2026-07-15/u/s/002.json"},
            ])

            pipeline.process_date(
                str(input_root),
                str(output_root),
                "2026-07-15",
                max_high_value_per_task_fingerprint_per_day=1,
                router_min_score=1.0,
            )

            selected = read_jsonl(output_root / "selected" / "sft" / "2026-07-15.jsonl")
            quality = read_jsonl(output_root / "quality" / "2026-07-15.jsonl")
            self.assertEqual(len(selected), 1)
            self.assertTrue(any("quota_exceeded" in item["quality"]["risk_labels"] for item in quality))

    def test_tool_result_before_matching_assistant_call_is_rejected_even_if_final_call_matches(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["tools"] = [
            {"type": "function", "function": {"name": "search", "parameters": {"type": "object"}}}
        ]
        raw["request_body"]["messages"] = [
            {"role": "user", "content": "查一下"},
            {"role": "tool", "tool_call_id": "call_1", "content": "result before call"},
        ]
        raw["response_body"]["choices"][0]["finish_reason"] = "tool_calls"
        raw["response_body"]["choices"][0]["message"] = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "search", "arguments": "{}"}}
            ],
        }
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        annotated = pipeline.annotate_task_and_quality(canonical, pipeline.default_selection_config())
        self.assertIsNone(pipeline.export_selected_tool_use_sft(annotated))
        self.assertIn("invalid_selected_tool_trace", annotated["quality"]["reject_reasons"])

    def test_tool_trace_rejects_duplicate_call_ids_across_history_and_response(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["tools"] = [
            {"type": "function", "function": {"name": "search", "parameters": {"type": "object"}}}
        ]
        raw["request_body"]["messages"] = [
            {"role": "user", "content": "查一下"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "search", "arguments": "{}"}}
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "historical result"},
        ]
        raw["response_body"]["choices"][0]["finish_reason"] = "tool_calls"
        raw["response_body"]["choices"][0]["message"] = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "search", "arguments": "{}"}}
            ],
        }
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        annotated = pipeline.annotate_task_and_quality(canonical, pipeline.default_selection_config())
        self.assertIsNone(pipeline.export_selected_tool_use_sft(annotated))
        self.assertIn("invalid_selected_tool_trace", annotated["quality"]["reject_reasons"])

    def test_compat_and_disable_diagnostics_output_matrices(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            compat_root = root / "compat"
            diag_root = root / "diag"
            day = input_root / "2026-07-15"
            raw = sample_success_record()
            raw["request_body"]["messages"] = [{"role": "user", "content": "请写 Python 代码"}]
            write_json(day / "u" / "s" / "001.json", raw)
            write_index(day, [{"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}])

            pipeline.process_date(str(input_root), str(compat_root), "2026-07-15", compat_output_set=True)
            self.assertTrue((compat_root / "sft" / "2026-07-15.jsonl").exists())
            self.assertFalse((compat_root / "selected" / "sft" / "2026-07-15.jsonl").exists())
            self.assertFalse((compat_root / "reports" / "2026-07-15.selection_manifest.json").exists())

            pipeline.process_date(str(input_root), str(diag_root), "2026-07-15", disable_diagnostics=True)
            self.assertFalse((diag_root / "canonical" / "2026-07-15.jsonl").exists())
            self.assertFalse((diag_root / "quality" / "2026-07-15.jsonl").exists())
            self.assertFalse((diag_root / "episodes" / "2026-07-15.jsonl").exists())
            self.assertTrue((diag_root / "selected" / "sft" / "2026-07-15.jsonl").exists())
            manifest = json.loads((diag_root / "reports" / "2026-07-15.selection_manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["output_matrix"]["disable_diagnostics"])


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

    def test_process_date_outputs_parse_and_counts_match_manifest(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            write_json(day / "u" / "s" / "001.json", sample_success_record())
            bad = sample_success_record()
            bad["status"] = "failed"
            write_json(day / "u" / "s" / "002.json", bad)
            (day / "_request_index.jsonl").write_text(
                json.dumps({"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}) + "\n"
                + json.dumps({"request_id": "request-2", "file_path": "2026-07-15/u/s/002.json"}) + "\n",
                encoding="utf-8",
            )

            result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

            canonical_lines = (output_root / "canonical" / "2026-07-15.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
            reject_lines = (output_root / "reports" / "2026-07-15.rejects.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
            stats = json.loads(
                (output_root / "reports" / "2026-07-15.stats.json").read_text(encoding="utf-8")
            )
            manifest = json.loads(
                (output_root / "manifests" / "2026-07-15.manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result["accepted"], 1)
            self.assertEqual(len([json.loads(line) for line in canonical_lines]), 1)
            self.assertEqual(len([json.loads(line) for line in reject_lines]), 1)
            self.assertEqual(stats["accepted"], manifest["accepted"])
            self.assertEqual(stats["rejected"], manifest["rejected"])
            self.assertEqual(manifest["files_loaded"], 2)

    def test_collect_outputs_skips_none_exporter_records(self):
        pipeline = load_pipeline_module()
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            sample_success_record(),
        )
        self.assertIsNone(reject)
        canonical["response"]["finish_reason"] = "length"
        outputs = pipeline.collect_outputs(
            "2026-07-15",
            [canonical],
            [],
            [],
            {"accepted": 1, "rejected": 0},
            {"accepted": 1, "rejected": 0},
        )
        self.assertEqual(outputs["sft/2026-07-15.jsonl"], [])
        self.assertNotIn(None, outputs["sft/2026-07-15.jsonl"])

    def test_process_date_rejects_do_not_include_raw_messages(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            raw = sample_success_record()
            raw["status"] = "failed"
            write_json(day / "u" / "s" / "001.json", raw)
            (day / "_request_index.jsonl").write_text(
                json.dumps({"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}) + "\n",
                encoding="utf-8",
            )
            pipeline.process_date(str(input_root), str(output_root), "2026-07-15")
            rejects = (output_root / "reports" / "2026-07-15.rejects.jsonl").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("messages", rejects)
            self.assertNotIn("13800138000", rejects)

    def test_process_date_hashes_file_paths_in_canonical_and_rejects(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            raw_path = "2026-07-15/tenant-1/user-1/session-1/001.json"
            write_json(input_root / raw_path, sample_success_record())
            (day / "_request_index.jsonl").write_text(
                json.dumps({"request_id": "request-1", "file_path": raw_path}) + "\n"
                + json.dumps({"request_id": "missing", "file_path": "2026-07-15/tenant-1/user-1/session-1/missing.json"}) + "\n",
                encoding="utf-8",
            )
            pipeline.process_date(str(input_root), str(output_root), "2026-07-15")
            canonical_text = (output_root / "canonical" / "2026-07-15.jsonl").read_text(encoding="utf-8")
            rejects_text = (output_root / "reports" / "2026-07-15.rejects.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("tenant-1/user-1/session-1", canonical_text)
            self.assertNotIn("tenant-1/user-1/session-1", rejects_text)
            canonical = json.loads(canonical_text)
            reject = json.loads(rejects_text)
            self.assertIn("file_path_hash", canonical["source"])
            self.assertNotIn("file_path_hash", reject)
            self.assertNotIn("request_id", reject)

    def test_process_date_rejects_detail_with_non_standard_json_constant(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            detail = day / "u" / "s" / "001.json"
            detail.parent.mkdir(parents=True)
            detail.write_text('{"request_id":"request-1","status":"success","value":Infinity}', encoding="utf-8")
            (day / "_request_index.jsonl").write_text(
                json.dumps({"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}) + "\n",
                encoding="utf-8",
            )
            result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15")
            self.assertEqual(result["accepted"], 0)
            self.assertEqual(result["rejected"], 1)
            self.assertEqual(result["reject_reasons"], {"bad_detail_json": 1})
            self.assertEqual(
                (output_root / "canonical" / "2026-07-15.jsonl").read_text(encoding="utf-8"),
                "",
            )

    def test_process_date_accepts_large_non_usage_integers(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            detail = day / "u" / "s" / "001.json"
            raw = sample_success_record()
            raw["timestamp_ms"] = 1712345678901
            write_json(detail, raw)
            (day / "_request_index.jsonl").write_text(
                json.dumps({"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}) + "\n",
                encoding="utf-8",
            )
            result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15")
            self.assertEqual(result["accepted"], 1)
            self.assertEqual(result["rejected"], 0)
            canonical_lines = (output_root / "canonical" / "2026-07-15.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(canonical_lines), 1)

    def test_process_date_rejects_overflow_float_detail_and_continues(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            bad_detail = day / "u" / "s" / "001.json"
            good_detail = day / "u" / "s" / "002.json"
            bad_detail.parent.mkdir(parents=True)
            raw_json = json.dumps(sample_success_record(), ensure_ascii=False)
            raw_json = raw_json.replace('"prompt_tokens": 10', '"prompt_tokens": 1e9999')
            bad_detail.write_text(raw_json, encoding="utf-8")
            write_json(good_detail, sample_success_record())
            (day / "_request_index.jsonl").write_text(
                json.dumps({"request_id": "bad", "file_path": "2026-07-15/u/s/001.json"}) + "\n"
                + json.dumps({"request_id": "good", "file_path": "2026-07-15/u/s/002.json"}) + "\n",
                encoding="utf-8",
            )
            result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15")
            self.assertEqual(result["accepted"], 1)
            self.assertEqual(result["rejected"], 1)
            self.assertEqual(result["reject_reasons"], {"bad_detail_json": 1})
            canonical_lines = (output_root / "canonical" / "2026-07-15.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(canonical_lines), 1)

    def test_process_date_route_labeler_requires_explicit_flag(self):
        pipeline = load_pipeline_module()
        old_env = os.environ.copy()
        original_urlopen = pipeline.urllib.request.urlopen

        def forbidden_urlopen(request, timeout=None):
            raise AssertionError("route labeler should be disabled without explicit flag")

        try:
            os.environ.clear()
            os.environ.update(old_env)
            os.environ.update({
                "AUDIT_LABEL_BASE_URL": "https://example.test/v1",
                "AUDIT_LABEL_API_KEY": "key",
                "AUDIT_LABEL_MODEL": "label-model",
            })
            pipeline.urllib.request.urlopen = forbidden_urlopen
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                input_root = root / "audit"
                output_root = root / "out"
                day = input_root / "2026-07-15"
                write_json(day / "u" / "s" / "001.json", sample_success_record())
                write_index(day, [{"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}])

                pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

                canonical = read_jsonl(output_root / "canonical" / "2026-07-15.jsonl")[0]
                router = read_jsonl(output_root / "router_classification" / "2026-07-15.jsonl")[0]
                self.assertIsNone(canonical["routing"]["model_label"])
                self.assertIsNone(router["labels"]["model_label"])
                self.assertEqual(router["labels"]["final_label"], "code_generation")
        finally:
            pipeline.urllib.request.urlopen = original_urlopen
            os.environ.clear()
            os.environ.update(old_env)

    def test_process_date_applies_successful_labeler_to_canonical_and_router(self):
        pipeline = load_pipeline_module()
        old_env = os.environ.copy()
        original_urlopen = pipeline.urllib.request.urlopen

        class FakeResponse(object):
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return json.dumps({
                    "choices": [{"message": {"content": '{"label":"tool_agent","confidence":0.91,"reason":"uses tools"}'}}]
                }).encode("utf-8")

        def fake_urlopen(request, timeout=None):
            return FakeResponse()

        try:
            os.environ.clear()
            os.environ.update(old_env)
            os.environ.update({
                "AUDIT_LABEL_BASE_URL": "https://example.test/v1",
                "AUDIT_LABEL_API_KEY": "key",
                "AUDIT_LABEL_MODEL": "label-model",
            })
            pipeline.urllib.request.urlopen = fake_urlopen
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                input_root = root / "audit"
                output_root = root / "out"
                day = input_root / "2026-07-15"
                write_json(day / "u" / "s" / "001.json", sample_success_record())
                (day / "_request_index.jsonl").write_text(
                    json.dumps({"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}) + "\n",
                    encoding="utf-8",
                )
                pipeline.process_date(str(input_root), str(output_root), "2026-07-15", enable_route_labeler=True)
                canonical = json.loads((output_root / "canonical" / "2026-07-15.jsonl").read_text(encoding="utf-8"))
                router = json.loads((output_root / "router_classification" / "2026-07-15.jsonl").read_text(encoding="utf-8"))
                self.assertEqual(canonical["routing"]["model_label"], {"label": "tool_agent", "confidence": 0.91})
                self.assertEqual(router["labels"]["model_label"], {"label": "tool_agent", "confidence": 0.91})
                self.assertEqual(router["labels"]["final_label"], "tool_agent")
                self.assertEqual(router["labels"]["confidence"], "high")
        finally:
            pipeline.urllib.request.urlopen = original_urlopen
            os.environ.clear()
            os.environ.update(old_env)

    def test_process_date_labeler_invalid_response_safely_degrades(self):
        pipeline = load_pipeline_module()
        old_env = os.environ.copy()
        original_urlopen = pipeline.urllib.request.urlopen

        class FakeResponse(object):
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return json.dumps({
                    "choices": [{"message": {"content": '{"label":"bad_label","confidence":0.99,"reason":"secret@example.com"}'}}]
                }).encode("utf-8")

        try:
            os.environ.clear()
            os.environ.update(old_env)
            os.environ.update({
                "AUDIT_LABEL_BASE_URL": "https://example.test/v1",
                "AUDIT_LABEL_API_KEY": "key",
                "AUDIT_LABEL_MODEL": "label-model",
            })
            pipeline.urllib.request.urlopen = lambda request, timeout=None: FakeResponse()
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                input_root = root / "audit"
                output_root = root / "out"
                day = input_root / "2026-07-15"
                write_json(day / "u" / "s" / "001.json", sample_success_record())
                (day / "_request_index.jsonl").write_text(
                    json.dumps({"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}) + "\n",
                    encoding="utf-8",
                )
                result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15", enable_route_labeler=True)
                router_text = (output_root / "router_classification" / "2026-07-15.jsonl").read_text(encoding="utf-8")
                router = json.loads(router_text)
                self.assertEqual(result["accepted"], 1)
                self.assertIsNone(router["labels"]["model_label"])
                self.assertEqual(router["labels"]["final_label"], "code_generation")
                self.assertNotIn("secret@example.com", router_text)
        finally:
            pipeline.urllib.request.urlopen = original_urlopen
            os.environ.clear()
            os.environ.update(old_env)

    def test_process_date_labeler_bad_url_safely_degrades(self):
        pipeline = load_pipeline_module()
        old_env = os.environ.copy()
        try:
            os.environ.clear()
            os.environ.update(old_env)
            os.environ.update({
                "AUDIT_LABEL_BASE_URL": "::::",
                "AUDIT_LABEL_API_KEY": "key",
                "AUDIT_LABEL_MODEL": "label-model",
            })
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                input_root = root / "audit"
                output_root = root / "out"
                day = input_root / "2026-07-15"
                write_json(day / "u" / "s" / "001.json", sample_success_record())
                (day / "_request_index.jsonl").write_text(
                    json.dumps({"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}) + "\n",
                    encoding="utf-8",
                )
                result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15", enable_route_labeler=True)
                router_text = (output_root / "router_classification" / "2026-07-15.jsonl").read_text(encoding="utf-8")
                router = json.loads(router_text)
                self.assertEqual(result["accepted"], 1)
                self.assertEqual(router["labels"]["final_label"], "code_generation")
                self.assertIsNone(router["labels"]["model_label"])
                self.assertNotIn("ValueError", router_text)
                self.assertNotIn("unknown url type", router_text)
        finally:
            os.environ.clear()
            os.environ.update(old_env)

    def test_process_date_dry_run_leaves_no_outputs_or_tmp(self):
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
            pipeline.process_date(str(input_root), str(output_root), "2026-07-15", dry_run=True)
            self.assertFalse((output_root / "canonical" / "2026-07-15.jsonl").exists())
            self.assertFalse((output_root / ".tmp" / "2026-07-15").exists())

    def test_process_date_limit_counts_detail_attempts_not_index_errors(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            write_json(day / "u" / "s" / "001.json", sample_success_record())
            (day / "_request_index.jsonl").write_text(
                "{bad json}\n"
                + json.dumps({"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"}) + "\n",
                encoding="utf-8",
            )
            result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15", limit=1)
            self.assertEqual(result["accepted"], 1)
            self.assertEqual(result["rejected"], 1)
            self.assertEqual(result["files_loaded"], 1)

    def test_process_date_limit_counts_missing_detail_attempt(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            write_json(day / "u" / "s" / "002.json", sample_success_record())
            (day / "_request_index.jsonl").write_text(
                json.dumps({"request_id": "missing", "file_path": "2026-07-15/u/s/missing.json"}) + "\n"
                + json.dumps({"request_id": "request-1", "file_path": "2026-07-15/u/s/002.json"}) + "\n",
                encoding="utf-8",
            )

            result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15", limit=1, dry_run=True)

            self.assertEqual(result["accepted"], 0)
            self.assertEqual(result["rejected"], 1)
            self.assertEqual(result["files_loaded"], 0)
            self.assertEqual(result["files_attempted"], 1)


    def test_write_outputs_atomically_rolls_back_when_replace_fails(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            output_root = pathlib.Path(tmp) / "out"
            old_canonical = output_root / "canonical" / "2026-07-15.jsonl"
            old_stats = output_root / "reports" / "2026-07-15.stats.json"
            old_canonical.parent.mkdir(parents=True)
            old_stats.parent.mkdir(parents=True)
            old_canonical.write_text('{"old":"canonical"}\n', encoding="utf-8")
            old_stats.write_text('{"old":"stats"}', encoding="utf-8")
            outputs = {
                "canonical/2026-07-15.jsonl": [{"new": "canonical"}],
                "reports/2026-07-15.stats.json": {"new": "stats"},
            }
            original_replace = pipeline.os.replace
            calls = []

            def fail_second_replace(src, dst):
                calls.append((src, dst))
                if len(calls) == 2:
                    raise OSError("injected replace failure")
                original_replace(src, dst)

            pipeline.os.replace = fail_second_replace
            try:
                with self.assertRaises(OSError):
                    pipeline.write_outputs_atomically(str(output_root), "2026-07-15", outputs)
            finally:
                pipeline.os.replace = original_replace

            self.assertEqual(old_canonical.read_text(encoding="utf-8"), '{"old":"canonical"}\n')
            self.assertEqual(old_stats.read_text(encoding="utf-8"), '{"old":"stats"}')
            self.assertFalse((output_root / ".tmp" / "2026-07-15").exists())
            self.assertFalse((output_root / ".tmp" / "2026-07-15.backup").exists())

    def test_write_outputs_rejects_non_standard_json_without_touching_old_final(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            output_root = pathlib.Path(tmp) / "out"
            old_path = output_root / "canonical" / "2026-07-15.jsonl"
            old_path.parent.mkdir(parents=True)
            old_path.write_text('{"old":true}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                pipeline.write_outputs_atomically(
                    str(output_root),
                    "2026-07-15",
                    {"canonical/2026-07-15.jsonl": [{"value": float("nan")}]},
                )
            self.assertEqual(old_path.read_text(encoding="utf-8"), '{"old":true}\n')

    def test_write_outputs_rejects_unsafe_relative_paths(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            output_root = pathlib.Path(tmp) / "out"
            with self.assertRaises(ValueError):
                pipeline.write_outputs_atomically(
                    str(output_root),
                    "2026-07-15",
                    {"../escape.jsonl": [{"bad": True}]},
                )
            self.assertFalse((pathlib.Path(tmp) / "escape.jsonl").exists())

    def test_process_date_rejects_unsafe_detail_path_without_reading_outside_root(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            day = input_root / "2026-07-15"
            write_json(root / "secret.json", sample_success_record())
            day.mkdir(parents=True)
            (day / "_request_index.jsonl").write_text(
                json.dumps({"request_id": "escape", "file_path": "../secret.json"}) + "\n",
                encoding="utf-8",
            )

            result = pipeline.process_date(str(input_root), str(output_root), "2026-07-15", dry_run=True)

            self.assertEqual(result["accepted"], 0)
            self.assertEqual(result["rejected"], 1)
            self.assertEqual(result["files_attempted"], 1)
            self.assertEqual(result["reject_reasons"], {"unsafe_detail_path": 1})

    def test_process_date_rejects_invalid_dates_before_writing(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            input_root = root / "audit"
            output_root = root / "out"
            for bad_date in ["../2026-07-15", "2026-7-15"]:
                with self.subTest(date=bad_date):
                    with self.assertRaises(ValueError):
                        pipeline.process_date(str(input_root), str(output_root), bad_date)
            self.assertFalse((root / "2026-07-15").exists())
            self.assertFalse(output_root.exists())


    def test_write_outputs_rejects_tmp_symlink_without_deleting_final(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            output_root = pathlib.Path(tmp) / "out"
            final = output_root / "canonical" / "old.jsonl"
            final.parent.mkdir(parents=True)
            final.write_text("old-final\n", encoding="utf-8")
            tmp_parent = output_root / ".tmp"
            tmp_parent.mkdir()
            (tmp_parent / "2026-07-15").symlink_to("../canonical")

            with self.assertRaises(ValueError):
                pipeline.write_outputs_atomically(
                    str(output_root),
                    "2026-07-15",
                    {"canonical/2026-07-15.jsonl": [{"new": True}]},
                )

            self.assertTrue(final.exists())
            self.assertEqual(final.read_text(encoding="utf-8"), "old-final\n")

    def test_process_date_cleans_tmp_when_writer_open_fails(self):
        pipeline = load_pipeline_module()
        original_outputs = pipeline.JSONL_OUTPUTS
        try:
            pipeline.JSONL_OUTPUTS = (
                "canonical/%s.jsonl",
                "../bad/%s.jsonl",
            )
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

                with self.assertRaises(ValueError):
                    pipeline.process_date(str(input_root), str(output_root), "2026-07-15")

                self.assertFalse((output_root / ".tmp" / "2026-07-15").exists())
                self.assertFalse((output_root / ".tmp" / "2026-07-15.backup").exists())
        finally:
            pipeline.JSONL_OUTPUTS = original_outputs

    def test_write_outputs_rolls_back_new_final_and_restores_old_final(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            output_root = pathlib.Path(tmp) / "out"
            new_final = output_root / "canonical" / "2026-07-15.jsonl"
            old_final = output_root / "reports" / "2026-07-15.stats.json"
            old_final.parent.mkdir(parents=True)
            old_final.write_text('{"old":"stats"}', encoding="utf-8")
            outputs = {
                "canonical/2026-07-15.jsonl": [{"new": "canonical"}],
                "reports/2026-07-15.stats.json": {"new": "stats"},
            }
            original_replace = pipeline.os.replace
            calls = []

            def fail_third_replace(src, dst):
                calls.append((src, dst))
                if len(calls) == 3:
                    raise OSError("injected replace failure")
                original_replace(src, dst)

            pipeline.os.replace = fail_third_replace
            try:
                with self.assertRaises(OSError):
                    pipeline.write_outputs_atomically(str(output_root), "2026-07-15", outputs)
            finally:
                pipeline.os.replace = original_replace

            self.assertFalse(new_final.exists())
            self.assertEqual(old_final.read_text(encoding="utf-8"), '{"old":"stats"}')
            self.assertFalse((output_root / ".tmp" / "2026-07-15").exists())
            self.assertFalse((output_root / ".tmp" / "2026-07-15.backup").exists())


    def test_write_outputs_preserves_backup_when_rollback_restore_fails(self):
        pipeline = load_pipeline_module()
        with tempfile.TemporaryDirectory() as tmp:
            output_root = pathlib.Path(tmp) / "out"
            old_final = output_root / "canonical" / "2026-07-15.jsonl"
            old_final.parent.mkdir(parents=True)
            old_final.write_text('old-canonical\n', encoding="utf-8")
            outputs = {
                "canonical/2026-07-15.jsonl": [{"new": "canonical"}],
            }
            original_replace = pipeline.os.replace
            calls = []

            def fail_forward_and_rollback(src, dst):
                calls.append((src, dst))
                if len(calls) in (2, 3):
                    raise OSError("injected replace failure")
                original_replace(src, dst)

            pipeline.os.replace = fail_forward_and_rollback
            try:
                with self.assertRaises(RuntimeError) as context:
                    pipeline.write_outputs_atomically(str(output_root), "2026-07-15", outputs)
            finally:
                pipeline.os.replace = original_replace

            self.assertIn("rollback_failed", str(context.exception))
            backup = output_root / ".tmp" / "2026-07-15.backup" / "canonical" / "2026-07-15.jsonl"
            self.assertTrue(backup.exists())
            self.assertEqual(backup.read_text(encoding="utf-8"), 'old-canonical\n')
            self.assertFalse((output_root / ".tmp" / "2026-07-15").exists())

    def test_main_guard_stays_after_pipeline_run_tests(self):
        source = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertGreater(
            source.rfind('if __name__ == "__main__":'),
            source.rfind("class PipelineRunTest"),
        )

if __name__ == "__main__":
    unittest.main()
