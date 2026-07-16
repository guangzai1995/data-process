import importlib.util
import json
import pathlib
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
        self.assertEqual(pipeline.PIPELINE_VERSION, "2026.07.16")


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
                "[]\n"
                "{\"request_id\":\"r2\",\"file_path\":\"2026-07-15/u/s/002.json\"}\n",
                encoding="utf-8",
            )
            events = list(pipeline.iter_index_records(root, "2026-07-15"))
            records = [record for record, error in events if record is not None]
            errors = [error for record, error in events if error is not None]
            self.assertEqual([record["request_id"] for record in records], ["r1", "r2"])
            self.assertEqual(
                [error["reason"] for error in errors],
                ["bad_index_json", "bad_index_record"],
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

    def test_build_canonical_sample_redacts_sensitive_dict_keys(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["messages"] = [
            {
                "role": "user",
                "content": {
                    "13800138000": "phone key",
                    "+86 13800138000": "second phone key",
                    "secret@example.com": "email key",
                    "api_key=abcdefghijklmnopqrstuvwxyz123456": "secret key",
                },
            }
        ]
        canonical, reject = pipeline.build_canonical_sample(
            "2026-07-15",
            {"request_id": "request-1", "file_path": "2026-07-15/u/s/001.json"},
            raw,
        )
        self.assertIsNone(reject)
        dumped = json.dumps(canonical, ensure_ascii=False)
        self.assertNotIn("13800138000", dumped)
        self.assertNotIn("secret@example.com", dumped)
        self.assertNotIn("api_key=abcdefghijklmnopqrstuvwxyz123456", dumped)
        redacted_content = canonical["request"]["messages"][0]["content"]
        self.assertEqual(len(redacted_content), 4)
        self.assertIn("<PHONE_1>", redacted_content)
        self.assertIn("<PHONE_1>__2", redacted_content)
        self.assertIn("<EMAIL_1>", redacted_content)
        self.assertIn("<SECRET_1>", redacted_content)
        self.assertTrue(canonical["quality"]["pii_redacted"])
        self.assertGreaterEqual(canonical["quality"]["redaction_stats"]["phone"], 2)
        self.assertGreaterEqual(canonical["quality"]["redaction_stats"]["email"], 1)
        self.assertGreaterEqual(canonical["quality"]["redaction_stats"]["secret"], 1)

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
                    {"role": "user", "content": {"13800138000": "call me"}}
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
        self.assertEqual(router["labels"]["final_label"], "code_generation")
        self.assertEqual(router["labels"]["confidence"], "medium")
        self.assertEqual(
            router["labels"]["model_label"],
            {"label": "tool_agent", "confidence": 0.74},
        )


    def test_export_sft_rebuilds_messages_as_text_only(self):
        pipeline = load_pipeline_module()
        raw = sample_success_record()
        raw["request_body"]["messages"] = [
            {
                "role": "system",
                "content": {"debug": "do not export"},
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


if __name__ == "__main__":
    unittest.main()
