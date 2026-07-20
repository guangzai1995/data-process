import importlib.util
import json
import pathlib
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "synthesize_training_samples.py"


def load_synth_module():
    spec = importlib.util.spec_from_file_location(
        "synthesize_training_samples", str(MODULE_PATH)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EnvFileTest(unittest.TestCase):
    def test_load_env_file_parses_values_without_exporting_secret(self):
        synth = load_synth_module()
        with tempfile.TemporaryDirectory() as tmp:
            env_path = pathlib.Path(tmp) / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "# local only",
                        "DEEPSEEK_API_KEY='secret-key'",
                        "DEEPSEEK_MODEL=deepseek-v4-flash",
                        "EMPTY=",
                    ]
                ),
                encoding="utf-8",
            )

            env = synth.load_env_file(env_path)

        self.assertEqual(env["DEEPSEEK_API_KEY"], "secret-key")
        self.assertEqual(env["DEEPSEEK_MODEL"], "deepseek-v4-flash")
        self.assertEqual(env["EMPTY"], "")


class SyntheticParsingTest(unittest.TestCase):
    def test_parse_model_samples_accepts_supported_training_shapes(self):
        synth = load_synth_module()
        content = json.dumps(
            {
                "samples": [
                    {
                        "task_type": "sft",
                        "topic": "python_debugging",
                        "messages": [{"role": "user", "content": "写一个排序函数"}],
                        "response": "可以使用 sorted。",
                    },
                    {
                        "task_type": "router",
                        "topic": "routing",
                        "input": "请写 SQL 查询",
                        "label": "code_generation",
                    },
                    {
                        "task_type": "tool_use_sft",
                        "topic": "tool",
                        "messages": [{"role": "user", "content": "查一下天气"}],
                        "tools": [
                            {"type": "function", "function": {"name": "weather"}}
                        ],
                        "response_message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "weather",
                                        "arguments": "{\"city\":\"北京\"}",
                                    },
                                }
                            ],
                        },
                    },
                ]
            },
            ensure_ascii=False,
        )

        records = synth.parse_model_samples(
            content,
            generator_model="deepseek-v4-flash",
            batch_index=0,
            created_at="2026-07-19T00:00:00Z",
        )

        self.assertEqual([record["task_type"] for record in records], [
            "sft",
            "router",
            "tool_use_sft",
        ])
        self.assertEqual(len({record["sample_id"] for record in records}), 3)
        for record in records:
            self.assertEqual(record["source"]["type"], "synthetic")
            self.assertEqual(record["source"]["generator_model"], "deepseek-v4-flash")

    def test_sample_id_ignores_source_metadata(self):
        synth = load_synth_module()
        sample = {
            "task_type": "router",
            "topic": "routing",
            "input": "classify this request",
            "label": "reasoning",
            "source": {"type": "synthetic", "created_at": "first"},
        }
        first = synth.sample_id_for(sample)
        sample["source"] = {"type": "synthetic", "created_at": "second"}

        self.assertEqual(synth.sample_id_for(sample), first)

    def test_parse_model_samples_accepts_top_level_sample_array(self):
        synth = load_synth_module()
        content = json.dumps(
            [
                {
                    "task_type": "router",
                    "topic": "routing",
                    "input": "请判断这个请求应该走哪个模型",
                    "label": "reasoning",
                }
            ],
            ensure_ascii=False,
        )

        records = synth.parse_model_samples(
            content,
            generator_model="deepseek-v4-flash",
            batch_index=1,
            created_at="2026-07-20T00:00:00Z",
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["task_type"], "router")

    def test_parse_model_samples_skips_invalid_schema_when_safe_records_remain(self):
        synth = load_synth_module()
        content = json.dumps(
            {
                "samples": [
                    {
                        "task_type": "tool_use_sft",
                        "topic": "bad_tool",
                        "messages": [{"role": "user", "content": "查一下天气"}],
                        "tools": [{"function": {"name": "weather"}}],
                        "response_message": {"role": "assistant", "content": None, "tool_calls": []},
                    },
                    {
                        "task_type": "router",
                        "topic": "routing",
                        "input": "请分析这个问题的解题步骤",
                        "label": "reasoning",
                    },
                ]
            },
            ensure_ascii=False,
        )

        records = synth.parse_model_samples(
            content,
            generator_model="deepseek-v4-flash",
            batch_index=3,
            created_at="2026-07-20T00:00:00Z",
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["task_type"], "router")

    def test_parse_model_samples_rejects_raw_audit_like_fields(self):
        synth = load_synth_module()
        content = json.dumps(
            {
                "samples": [
                    {
                        "task_type": "sft",
                        "topic": "bad",
                        "request_id": "real-request",
                        "messages": [{"role": "user", "content": "hello"}],
                        "response": "world",
                    }
                ]
            }
        )

        with self.assertRaises(ValueError):
            synth.parse_model_samples(
                content,
                generator_model="deepseek-v4-flash",
                batch_index=0,
                created_at="2026-07-19T00:00:00Z",
            )


class RunnerTest(unittest.TestCase):
    def test_run_synthesis_resumes_from_existing_output(self):
        synth = load_synth_module()
        calls = []

        def fake_generate(config, batch_index, batch_size, urlopen=None):
            calls.append((batch_index, batch_size))
            return [
                {
                    "sample_id": "synthetic-existing",
                    "task_type": "sft",
                    "source": {"type": "synthetic"},
                },
                {
                    "sample_id": "synthetic-new",
                    "task_type": "router",
                    "source": {"type": "synthetic"},
                },
            ]

        with tempfile.TemporaryDirectory() as tmp:
            output_root = pathlib.Path(tmp) / "synthetic"
            output_root.mkdir()
            output_file = output_root / "samples.jsonl"
            output_file.write_text(
                json.dumps(
                    {
                        "sample_id": "synthetic-existing",
                        "task_type": "sft",
                        "source": {"type": "synthetic"},
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            result = synth.run_synthesis(
                {
                    "api_key": "key",
                    "base_url": "https://api.deepseek.com",
                    "model": "deepseek-v4-flash",
                    "timeout": 30,
                },
                output_root,
                target_count=2,
                batch_size=2,
                generate_batch=fake_generate,
                created_at=lambda: "2026-07-19T00:00:00Z",
            )

            lines = output_file.read_text(encoding="utf-8").splitlines()
            state = json.loads((output_root / "state.json").read_text(encoding="utf-8"))

        self.assertEqual(result["written"], 1)
        self.assertEqual(result["completed"], 2)
        self.assertEqual(len(lines), 2)
        self.assertEqual(state["completed"], 2)
        self.assertEqual(calls, [(1, 2)])

    def test_generate_batch_uses_json_mode_and_retries_invalid_content(self):
        synth = load_synth_module()
        calls = []
        valid_content = json.dumps(
            {
                "samples": [
                    {
                        "task_type": "router",
                        "topic": "routing",
                        "input": "请判断这个请求应该走哪个模型",
                        "label": "reasoning",
                    }
                ]
            },
            ensure_ascii=False,
        )

        class FakeResponse(object):
            def __init__(self, content):
                self.content = content

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return json.dumps(
                    {
                        "choices": [
                            {"message": {"content": self.content}, "finish_reason": "stop"}
                        ]
                    }
                ).encode("utf-8")

        def fake_urlopen(request, timeout=None):
            body = json.loads(request.data.decode("utf-8"))
            calls.append(body)
            if len(calls) == 1:
                return FakeResponse("not json")
            return FakeResponse(valid_content)

        records = synth.generate_batch(
            {
                "api_key": "key",
                "base_url": "https://api.deepseek.com",
                "model": "deepseek-v4-flash",
                "timeout": 30,
                "max_retries": 2,
            },
            batch_index=2,
            batch_size=1,
            urlopen=fake_urlopen,
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["response_format"], {"type": "json_object"})
        self.assertEqual(calls[0]["thinking"], {"type": "disabled"})



if __name__ == "__main__":
    unittest.main()
