#!/usr/bin/env python3
"""Generate synthetic training samples without reading real audit data."""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import sys
import urllib.request


DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-flash"
DEFAULT_OUTPUT_ROOT = "audit_training/synthetic_samples"
DEFAULT_TARGET_COUNT = 20
DEFAULT_BATCH_SIZE = 5
DEFAULT_TIMEOUT = 30

SUPPORTED_TASK_TYPES = set(["sft", "router", "tool_use_sft"])
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
AUDIT_LIKE_KEYS = set([
    "request_id",
    "file_path",
    "tenant_id",
    "user_id",
    "api_key_id",
    "client_ip",
    "session_id",
    "request_body",
    "response_body",
    "tenant_hash",
    "user_hash",
    "session_hash",
])


def utc_now():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def load_env_file(path):
    env = {}
    path = pathlib.Path(path)
    if not path.exists():
        return env
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            if key:
                env[key] = value
    return env


def merged_env(env_file):
    merged = dict(os.environ)
    merged.update(load_env_file(env_file))
    return merged


def positive_int(value, name):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise SystemExit("%s must be an integer" % name)
    if parsed <= 0:
        raise SystemExit("%s must be greater than 0" % name)
    return parsed


def load_config(args):
    env = merged_env(args.env_file)
    api_key = env.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        raise SystemExit("DEEPSEEK_API_KEY is required in %s" % args.env_file)
    return {
        "api_key": api_key,
        "base_url": env.get("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
        "model": env.get("DEEPSEEK_MODEL", DEFAULT_MODEL),
        "timeout": positive_int(env.get("DEEPSEEK_TIMEOUT", DEFAULT_TIMEOUT), "DEEPSEEK_TIMEOUT"),
    }


def stable_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sample_id_for(sample):
    payload = dict(sample)
    payload.pop("sample_id", None)
    payload.pop("source", None)
    digest = hashlib.sha256(stable_json(payload).encode("utf-8")).hexdigest()
    return "synthetic-" + digest[:24]


def contains_audit_like_key(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in AUDIT_LIKE_KEYS:
                return True
            if contains_audit_like_key(item):
                return True
    elif isinstance(value, list):
        for item in value:
            if contains_audit_like_key(item):
                return True
    return False


def text_from_response_payload(payload):
    if not isinstance(payload, dict):
        return None
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    choice = choices[0]
    if not isinstance(choice, dict):
        return None
    message = choice.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if not isinstance(content, str):
        return None
    return content


def strip_json_fence(text):
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines:
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    return stripped


def valid_text_messages(messages):
    if not isinstance(messages, list) or not messages:
        return False
    for message in messages:
        if not isinstance(message, dict):
            return False
        role = message.get("role")
        content = message.get("content")
        if role not in ("system", "user", "assistant"):
            return False
        if not isinstance(content, str) or not content.strip():
            return False
    return True


def valid_tool_definition(tool):
    if not isinstance(tool, dict) or tool.get("type") != "function":
        return False
    function = tool.get("function")
    if not isinstance(function, dict):
        return False
    return isinstance(function.get("name"), str) and bool(function.get("name"))


def valid_tool_call(tool_call):
    if not isinstance(tool_call, dict):
        return False
    if not isinstance(tool_call.get("id"), str) or not tool_call.get("id"):
        return False
    if tool_call.get("type") != "function":
        return False
    function = tool_call.get("function")
    if not isinstance(function, dict):
        return False
    if not isinstance(function.get("name"), str) or not function.get("name"):
        return False
    return isinstance(function.get("arguments"), str)


def normalize_sft(sample):
    messages = sample.get("messages")
    response = sample.get("response")
    if not valid_text_messages(messages):
        raise ValueError("invalid sft messages")
    if not isinstance(response, str) or not response.strip():
        raise ValueError("invalid sft response")
    return {
        "task_type": "sft",
        "topic": str(sample.get("topic") or "general"),
        "messages": messages,
        "response": response.strip(),
    }


def normalize_router(sample):
    label = sample.get("label")
    input_text = sample.get("input")
    if label not in ROUTE_LABELS:
        raise ValueError("invalid router label")
    if not isinstance(input_text, str) or not input_text.strip():
        raise ValueError("invalid router input")
    return {
        "task_type": "router",
        "topic": str(sample.get("topic") or "routing"),
        "input": input_text.strip(),
        "label": label,
    }


def normalize_tool_use_sft(sample):
    messages = sample.get("messages")
    tools = sample.get("tools")
    response_message = sample.get("response_message")
    if not valid_text_messages(messages):
        raise ValueError("invalid tool messages")
    if not isinstance(tools, list) or not tools:
        raise ValueError("invalid tools")
    for tool in tools:
        if not valid_tool_definition(tool):
            raise ValueError("invalid tool definition")
    if not isinstance(response_message, dict):
        raise ValueError("invalid response message")
    tool_calls = response_message.get("tool_calls")
    if not isinstance(tool_calls, list) or not tool_calls:
        raise ValueError("invalid tool calls")
    for tool_call in tool_calls:
        if not valid_tool_call(tool_call):
            raise ValueError("invalid tool call")
    return {
        "task_type": "tool_use_sft",
        "topic": str(sample.get("topic") or "tool"),
        "messages": messages,
        "tools": tools,
        "response_message": response_message,
    }


def normalize_sample(sample):
    if not isinstance(sample, dict):
        raise ValueError("sample must be object")
    if contains_audit_like_key(sample):
        raise ValueError("synthetic sample contains audit-like field")
    task_type = sample.get("task_type")
    if task_type == "sft":
        return normalize_sft(sample)
    if task_type == "router":
        return normalize_router(sample)
    if task_type == "tool_use_sft":
        return normalize_tool_use_sft(sample)
    raise ValueError("unsupported task_type")


def parse_model_samples(content, generator_model, batch_index, created_at):
    try:
        payload = json.loads(strip_json_fence(content))
    except ValueError:
        raise ValueError("model response is not JSON")
    samples = payload.get("samples") if isinstance(payload, dict) else None
    if not isinstance(samples, list) or not samples:
        raise ValueError("model response must contain samples")
    records = []
    for raw_sample in samples:
        normalized = normalize_sample(raw_sample)
        normalized["source"] = {
            "type": "synthetic",
            "generator_model": generator_model,
            "batch_index": batch_index,
            "created_at": created_at,
        }
        normalized["sample_id"] = sample_id_for(normalized)
        records.append(normalized)
    return records


def synthetic_prompt(batch_index, batch_size):
    return (
        "Generate %d purely synthetic Chinese training samples. Do not use or mention "
        "real users, tenants, request IDs, file paths, logs, API keys, phone numbers, "
        "emails, or private data. Return only JSON with a top-level samples array. "
        "Each sample must use one task_type from sft, router, tool_use_sft. "
        "For sft include topic, messages, response. For router include topic, input, "
        "label using one of: %s. For tool_use_sft include topic, messages, tools, "
        "response_message with valid tool_calls. Batch index: %d."
    ) % (batch_size, ", ".join(sorted(ROUTE_LABELS)), batch_index)


def generate_batch(config, batch_index, batch_size, urlopen=None):
    body = json.dumps(
        {
            "model": config["model"],
            "messages": [
                {
                    "role": "system",
                    "content": "Return only valid compact JSON for synthetic training data.",
                },
                {"role": "user", "content": synthetic_prompt(batch_index, batch_size)},
            ],
            "temperature": 0.7,
            "max_tokens": 3000,
        },
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    request = urllib.request.Request(
        config["base_url"] + "/chat/completions",
        data=body,
        headers={
            "Authorization": "Bearer " + config["api_key"],
            "Content-Type": "application/json",
        },
    )
    opener = urlopen or urllib.request.urlopen
    with opener(request, timeout=config["timeout"]) as response:
        payload = json.loads(response.read().decode("utf-8"))
    content = text_from_response_payload(payload)
    if content is None:
        raise ValueError("missing model response content")
    return parse_model_samples(
        content,
        generator_model=config["model"],
        batch_index=batch_index,
        created_at=utc_now(),
    )


def read_existing_ids(output_file):
    sample_ids = set()
    if not output_file.exists():
        return sample_ids
    with output_file.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except ValueError:
                continue
            sample_id = record.get("sample_id") if isinstance(record, dict) else None
            if isinstance(sample_id, str) and sample_id:
                sample_ids.add(sample_id)
    return sample_ids


def load_state(state_file):
    if not state_file.exists():
        return {}
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except ValueError:
        return {}


def write_state(state_file, state):
    tmp_file = state_file.with_name(state_file.name + ".tmp")
    with tmp_file.open("w", encoding="utf-8") as handle:
        handle.write(
            json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(str(tmp_file), str(state_file))


def append_record(output_file, record):
    with output_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def run_synthesis(config, output_root, target_count, batch_size, generate_batch=generate_batch, created_at=utc_now):
    output_root = pathlib.Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    output_file = output_root / "samples.jsonl"
    state_file = output_root / "state.json"
    sample_ids = read_existing_ids(output_file)
    state = load_state(state_file)
    completed = len(sample_ids)
    batch_index = int(state.get("next_batch_index", completed) or completed)
    written = 0

    write_state(
        state_file,
        {
            "completed": completed,
            "target_count": target_count,
            "next_batch_index": batch_index,
            "updated_at": created_at(),
        },
    )

    while completed < target_count:
        records = generate_batch(config, batch_index, batch_size)
        for record in records:
            sample_id = record.get("sample_id")
            if not isinstance(sample_id, str) or not sample_id or sample_id in sample_ids:
                continue
            append_record(output_file, record)
            sample_ids.add(sample_id)
            completed += 1
            written += 1
            write_state(
                state_file,
                {
                    "completed": completed,
                    "target_count": target_count,
                    "next_batch_index": batch_index + 1,
                    "updated_at": created_at(),
                },
            )
            if completed >= target_count:
                break
        batch_index += 1
    return {
        "completed": completed,
        "output_file": str(output_file),
        "state_file": str(state_file),
        "target_count": target_count,
        "written": written,
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Generate pure synthetic training samples with DeepSeek."
    )
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--target-count", type=lambda value: positive_int(value, "--target-count"), default=DEFAULT_TARGET_COUNT)
    parser.add_argument("--batch-size", type=lambda value: positive_int(value, "--batch-size"), default=DEFAULT_BATCH_SIZE)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    config = load_config(args)
    try:
        result = run_synthesis(
            config,
            args.output_root,
            target_count=args.target_count,
            batch_size=args.batch_size,
        )
    except KeyboardInterrupt:
        print("Interrupted. Re-run the same command to resume.", file=sys.stderr)
        return 130
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
