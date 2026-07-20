#!/usr/bin/env python3
"""Clean audit logs into training-ready datasets."""

PIPELINE_VERSION = "2026.07.19"
DEFAULT_INPUT_ROOT = "/isos_data_share/audit"
DEFAULT_OUTPUT_ROOT = "audit_training"
CANONICAL_SCHEMA_VERSION = "audit_canonical.v2"
QUALITY_SCHEMA_VERSION = "audit_quality.v1"
EPISODE_SCHEMA_VERSION = "audit_episode.v1"
SELECTED_SCHEMA_VERSION = "selected_training.v1"
REPORT_SCHEMA_VERSION = "selection_report.v1"
LABEL_QUEUE_SCHEMA_VERSION = "label_queue.v2"
DEFAULT_K_THRESHOLD = 5
DEFAULT_MAX_IN_MEMORY_SAMPLES = 50000
DEFAULT_MAX_SELECTION_MEMORY_MB = 512
DEFAULT_LOCK_TTL_SECONDS = 24 * 60 * 60


import argparse
import calendar
import copy
import datetime
import errno
import hashlib
import hmac
import json
import math
import os
import pathlib
import re
import shutil
import socket
import sys
import time
import urllib.request
import uuid


REDACTION_PATTERNS = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("secret", re.compile(r"(?i)\b(?:bearer\s+)?(?:sk-|ak-|api[_-]?key[:=]?|secret[:=]?)[A-Za-z0-9_\-]{16,}\b")),
    ("phone", re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")),
    ("cn_id", re.compile(r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)")),
    ("bank_card", re.compile(r"(?<!\d)\d(?:[ -]?\d){15,18}(?!\d)")),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
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


def iter_index_records(input_root, date):
    root = pathlib.Path(input_root)
    index_path = root / date / "_request_index.jsonl"
    with index_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(
                    stripped,
                    parse_constant=reject_json_constant,
                    parse_float=parse_finite_float,
                )
            except ValueError:
                yield None, {"line": line_number, "reason": "bad_index_json"}
                continue
            if (
                not isinstance(record, dict)
                or not isinstance(record.get("request_id"), str)
                or not record.get("request_id")
                or not isinstance(record.get("file_path"), str)
                or not record.get("file_path")
            ):
                yield None, {"line": line_number, "reason": "bad_index_record"}
                continue
            record["_index_line"] = line_number
            record["_detail_sequence"] = line_number
            yield record, None



def stable_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_hash(value):
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def unique_redacted_key(redacted_dict, key):
    if key not in redacted_dict:
        return key
    suffix = 2
    while True:
        candidate = "%s__%d" % (key, suffix)
        if candidate not in redacted_dict:
            return candidate
        suffix += 1


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
            if isinstance(key, str):
                redacted_key, key_stats = redact_text(key)
            else:
                redacted_key, key_stats = key, {}
            redacted_key = unique_redacted_key(redacted_dict, redacted_key)
            redacted, stats = redact_value_tree(item)
            redacted_dict[redacted_key] = redacted
            for stat_key, count in key_stats.items():
                merged[stat_key] = merged.get(stat_key, 0) + count
            for stat_key, count in stats.items():
                merged[stat_key] = merged.get(stat_key, 0) + count
        return redacted_dict, merged
    return value, {}


def first_response_choice(raw_record):
    response_body = raw_record.get("response_body") or {}
    if not isinstance(response_body, dict):
        return None
    choices = response_body.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    choice = choices[0]
    if not isinstance(choice, dict):
        return None
    return choice


def response_message_from_choice(choice):
    message = choice.get("message") or {}
    if not isinstance(message, dict):
        return {}
    return message


def assistant_text_from_choice(choice):
    content = response_message_from_choice(choice).get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                text = part["text"].strip()
                if text:
                    parts.append(text)
        return "\n".join(parts)
    return ""


def merge_counts(*dicts):
    merged = {}
    for counts in dicts:
        for key, value in counts.items():
            merged[key] = merged.get(key, 0) + value
    return merged


def file_path_hash(index_record):
    return hash_identifier(index_record.get("file_path"))


def reject_record(date, index_record, reason):
    return {
        "date": date,
        "request_id": index_record.get("request_id"),
        "file_path_hash": file_path_hash(index_record),
        "reason": reason,
    }


def parse_event_time_ms(raw_record):
    value = raw_record.get("timestamp_ms")
    if isinstance(value, bool):
        value = None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return int(value)
    parsed = parse_timestamp_to_ms(raw_record.get("timestamp"))
    return parsed


def parse_timestamp_to_ms(value):
    if not isinstance(value, str) or not value:
        return None
    match = re.match(
        r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:?\d{2})?$",
        value,
    )
    if not match:
        return None
    year, month, day, hour, minute, second, fraction, tz = match.groups()
    try:
        dt = datetime.datetime(
            int(year), int(month), int(day), int(hour), int(minute), int(second)
        )
    except ValueError:
        return None
    epoch_seconds = calendar.timegm(dt.timetuple())
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset_seconds = sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
        epoch_seconds -= offset_seconds
    millis = epoch_seconds * 1000
    if fraction:
        millis += int((fraction + "000")[:3])
    return millis


def index_order_from_record(date, index_record):
    line = index_record.get("_index_line")
    sequence = index_record.get("_detail_sequence")
    try:
        line = int(line)
    except (TypeError, ValueError):
        line = 0
    try:
        sequence = int(sequence)
    except (TypeError, ValueError):
        sequence = line
    return [date, line, sequence]


def normalize_text(text):
    text = (text or "").strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text


def normalize_for_dedupe(text, max_chars=1200):
    text = normalize_text(text)
    if not text:
        return ""
    text = DEDUPE_URL_RE.sub(" <url> ", text)
    text = DEDUPE_PATH_RE.sub(" <path> ", text)
    text = DEDUPE_REDACTION_RE.sub(" <redacted> ", text)
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
    tokens = list(tokens)
    if not tokens:
        return 0
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
    return bin(left ^ right).count("1")


def jaccard_similarity(left_tokens, right_tokens):
    left = set(left_tokens)
    right = set(right_tokens)
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return float(len(left & right)) / float(len(left | right))


def hmac_digest(value, key, length=16):
    if not key:
        return ""
    digest = hmac.new(str(key).encode("utf-8"), str(value).encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:length]


def model_bucket(model):
    if not isinstance(model, str) or not model:
        return "unknown"
    lowered = model.lower()
    if "deepseek" in lowered:
        return "deepseek"
    if "glm" in lowered:
        return "glm"
    if "gpt" in lowered or "openai" in lowered:
        return "openai"
    if "qwen" in lowered:
        return "qwen"
    return "other"


def client_type_bucket(client_type):
    if not isinstance(client_type, str) or not client_type:
        return "unknown"
    lowered = client_type.lower()
    if lowered in ("opencode", "web", "api", "sdk", "cli"):
        return lowered
    return "other"


def token_bucket(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return "unknown"
    if parsed < 512:
        return "lt_512"
    if parsed < 4096:
        return "512_4k"
    if parsed < 16000:
        return "4k_16k"
    if parsed < 64000:
        return "16k_64k"
    return "gte_64k"


def score_bucket(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if score < 0.4:
        return "low"
    if score < 0.7:
        return "medium"
    if score < 0.9:
        return "high"
    return "excellent"


def count_redaction_hits(stats):
    return sum(value for value in (stats or {}).values() if isinstance(value, int))


USAGE_TOKEN_FIELDS = ("prompt_tokens", "completion_tokens", "total_tokens")
MAX_USAGE_TOKENS = 10 ** 9


def parse_finite_float(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def sanitize_usage(usage):
    if not isinstance(usage, dict):
        return None
    sanitized = {}
    for key in USAGE_TOKEN_FIELDS:
        if key not in usage:
            continue
        value = usage[key]
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            if value < 0 or value > MAX_USAGE_TOKENS:
                return None
        elif isinstance(value, float):
            if (
                not math.isfinite(value)
                or value < 0
                or not value.is_integer()
                or value > MAX_USAGE_TOKENS
            ):
                return None
            value = int(value)
        else:
            return None
        sanitized[key] = value
    return sanitized


def valid_message_content(content):
    if content is None:
        return False
    if isinstance(content, str):
        return True
    if not isinstance(content, list):
        return False
    for part in content:
        if isinstance(part, str):
            continue
        if not isinstance(part, dict):
            return False
        if "text" in part and not isinstance(part.get("text"), str):
            return False
    return True


def valid_messages(messages):
    if not isinstance(messages, list) or not messages:
        return False
    for message in messages:
        if not isinstance(message, dict):
            return False
        if not isinstance(message.get("role"), str):
            return False
        if "content" not in message:
            return False
        if not valid_message_content(message.get("content")):
            return False
    return True


def json_serializable(value):
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return False
    return True


def valid_function_payload(function, require_arguments=False):
    if not isinstance(function, dict):
        return False
    if not isinstance(function.get("name"), str) or not function.get("name"):
        return False
    if require_arguments and "arguments" not in function:
        return False
    if "arguments" in function and not isinstance(function.get("arguments"), str):
        return False
    if "description" in function and not isinstance(function.get("description"), str):
        return False
    if "parameters" in function and not isinstance(function.get("parameters"), dict):
        return False
    for optional_key in ("description", "parameters"):
        if optional_key in function and not json_serializable(function[optional_key]):
            return False
    return True


def valid_tools(tools):
    if not isinstance(tools, list):
        return False
    for tool in tools:
        if not isinstance(tool, dict):
            return False
        if tool.get("type") != "function":
            return False
        if not valid_function_payload(tool.get("function")):
            return False
    return True


def valid_tool_call(tool_call):
    if not isinstance(tool_call, dict):
        return False
    if not isinstance(tool_call.get("id"), str) or not tool_call.get("id"):
        return False
    if tool_call.get("type") != "function":
        return False
    return valid_function_payload(tool_call.get("function"), require_arguments=True)


def valid_response_message(message):
    if not isinstance(message, dict):
        return False
    tool_calls = message.get("tool_calls")
    has_tool_calls = tool_calls is not None
    if has_tool_calls:
        if not isinstance(tool_calls, list):
            return False
        for tool_call in tool_calls:
            if not valid_tool_call(tool_call):
                return False
    if "content" not in message:
        return has_tool_calls
    if message.get("content") is None:
        return has_tool_calls
    return valid_message_content(message.get("content"))


SAFE_REQUEST_PARAM_KEYS = (
    "model",
    "temperature",
    "top_p",
    "max_tokens",
    "presence_penalty",
    "frequency_penalty",
    "stop",
    "stream",
    "tool_choice",
    "response_format",
    "seed",
    "n",
)


def build_redacted_request_params(request_body, raw_record):
    params = {}
    stats = {}
    if isinstance(request_body, dict):
        for key in SAFE_REQUEST_PARAM_KEYS:
            if key in request_body:
                redacted, value_stats = redact_value_tree(request_body[key])
                params[key] = redacted
                stats = merge_counts(stats, value_stats)
    params["client_type"] = raw_record.get("client_type") or ""
    params["adapter_type"] = raw_record.get("adapter_type") or ""
    params["is_stream"] = bool(raw_record.get("is_stream"))
    return params, stats


def build_request_params(request_body, raw_record):
    params, _stats = build_redacted_request_params(request_body, raw_record)
    return params


def build_canonical_sample(date, index_record, raw_record, max_prompt_chars=200000, max_response_chars=100000):
    if raw_record.get("status") != "success":
        return None, reject_record(date, index_record, "status_not_success")
    request_body = raw_record.get("request_body") or {}
    if not isinstance(request_body, dict):
        return None, reject_record(date, index_record, "missing_messages")
    messages = request_body.get("messages")
    if not isinstance(messages, list) or not messages:
        return None, reject_record(date, index_record, "missing_messages")
    if not valid_messages(messages):
        return None, reject_record(date, index_record, "invalid_messages")
    tools = request_body.get("tools", [])
    if tools is None:
        tools = []
    if not valid_tools(tools):
        return None, reject_record(date, index_record, "invalid_tools")
    choice = first_response_choice(raw_record)
    if choice is None:
        return None, reject_record(date, index_record, "missing_choices")
    if not isinstance(choice.get("message"), dict):
        return None, reject_record(date, index_record, "invalid_response_message")
    response_message = response_message_from_choice(choice)
    if not valid_response_message(response_message):
        return None, reject_record(date, index_record, "invalid_response_message")
    usage = sanitize_usage((raw_record.get("response_body") or {}).get("usage"))
    if usage is None:
        return None, reject_record(date, index_record, "invalid_usage")
    response_text = assistant_text_from_choice(choice)
    if not response_text and not response_message.get("tool_calls"):
        return None, reject_record(date, index_record, "empty_assistant_response")
    if len(stable_json(messages)) > max_prompt_chars:
        return None, reject_record(date, index_record, "prompt_too_long")
    if len(stable_json(response_message)) > max_response_chars:
        return None, reject_record(date, index_record, "response_too_long")

    redacted_messages, message_stats = redact_value_tree(messages)
    redacted_tools, tool_stats = redact_value_tree(tools)
    redacted_response, response_stats = redact_value_tree(response_message)
    redacted_params, param_stats = build_redacted_request_params(request_body, raw_record)
    stats = merge_counts(message_stats, tool_stats, response_stats, param_stats)
    request_payload_for_hash = {
        "date": date,
        "request_id": raw_record.get("request_id") or index_record.get("request_id"),
        "messages": redacted_messages,
    }
    sample_id = hashlib.sha256(stable_json(request_payload_for_hash).encode("utf-8")).hexdigest()
    finish_reason = choice.get("finish_reason")
    event_time_ms = parse_event_time_ms(raw_record)
    event_time = raw_record.get("timestamp") if isinstance(raw_record.get("timestamp"), str) else None
    index_order = index_order_from_record(date, index_record)
    task_types = ["router"]
    if redacted_tools or redacted_response.get("tool_calls"):
        task_types.append("tool_use_sft")
    elif finish_reason != "length":
        task_types.append("sft")

    canonical = {
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "sample_id": sample_id,
        "source": {
            "date": date,
            "request_id": raw_record.get("request_id") or index_record.get("request_id"),
            "file_path_hash": file_path_hash(index_record),
            "tenant_hash": hash_identifier(raw_record.get("tenant_id")),
            "user_hash": hash_identifier(raw_record.get("user_id")),
            "session_hash": hash_identifier(raw_record.get("session_id")),
            "event_time": event_time,
            "event_time_ms": event_time_ms,
            "index_order": index_order,
            "index_order_only": event_time_ms is None,
        },
        "request": {
            "model": raw_record.get("model") or request_body.get("model"),
            "request_path": raw_record.get("request_path"),
            "messages": redacted_messages,
            "tools": redacted_tools,
            "tool_choice": redacted_params.get("tool_choice"),
            "params": redacted_params,
        },
        "response": {
            "message": redacted_response,
            "finish_reason": finish_reason,
            "usage": usage,
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
    route_label = classify_by_rules(canonical)
    intent_label = infer_intent_label(canonical)
    canonical["routing"]["rule_label"] = route_label
    canonical["task"] = {
        "route_label": route_label,
        "intent_label": intent_label,
        "task_fingerprint_internal": task_fingerprint_internal(canonical),
        "task_bucket": task_bucket_for(canonical, None),
        "episode_id_internal": None,
        "turn_index": 0,
    }
    return canonical, None

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


INTENT_LABELS = set([
    "answer_question",
    "write_code",
    "debug_code",
    "use_tool",
    "summarize_or_transform",
    "analyze_reason",
    "domain_lookup",
    "greeting_or_probe",
    "unknown",
])

VALUE_LABELS = set([
    "code_task",
    "tool_task",
    "reasoning_task",
    "domain_task",
    "multi_turn_task",
    "well_formed_response",
])

RISK_LABELS = set([
    "redaction_risk",
    "low_information",
    "invalid_selected_tool_trace",
    "length_finish",
    "duplicate",
    "quota_exceeded",
    "leakage_scan_failed",
    "near_duplicate",
    "debug_noise",
    "debug_burst",
    "dedupe_state_saturated",
])

GREETING_TEXTS = set(["hi", "hello", "hey", "你好", "您好", "嗨", "哈喽"])
CONTINUATION_TERMS = ("继续", "上面", "上一", "刚才", "前面", "接着", "继续上面的", "that", "previous")
DEDUPE_REDACTION_RE = re.compile(r"(?i)<[A-Z_]+_\d+>")
DEDUPE_URL_RE = re.compile(r"(?i)\bhttps?://\S+")
DEDUPE_PATH_SEGMENT = r"(?:[A-Za-z0-9_.-]+|<[A-Za-z_]+_\d+>)"
DEDUPE_PATH_RE = re.compile(
    r"(?:(?:^|\s)(?:/|\.\.?/|~[/\\]|[A-Za-z]:[\\/])\S+|"
    r"(?:^|\s)" + DEDUPE_PATH_SEGMENT + r"(?:[/\\]" + DEDUPE_PATH_SEGMENT + r")*[/\\][A-Za-z0-9_.-]*\.[A-Za-z0-9_.-]+)"
)
DEDUPE_NUMBER_RE = re.compile(r"(?<!\w)\d+(?:\.\d+)?(?!\w)")
DEDUPE_PUNCT_RE = re.compile(r"[，。！？；：、,.!?;:()/\\\[\]{}\"'`]+")
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

LEAKAGE_PATTERNS = [
    ("secret", re.compile(r"(?i)\b(?:bearer\s+)?(?:sk-|ak-|api[_-]?key[:=]?|secret[:=]?|token[:=]?)[A-Za-z0-9_\-]{12,}\b")),
    ("url", re.compile(r"(?i)\bhttps?://\S+")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone", re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")),
    ("cn_id", re.compile(r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)")),
    ("bank_card", re.compile(r"(?<!\d)\d(?:[ -]?\d){15,18}(?!\d)")),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("uuid", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("file_path", re.compile(r"(?:(?:^|\s)(?:/|\.\.?/|~[/\\]|[A-Za-z]:[\\/])[^\s]+|[\w.\-]+(?:/|\\)[\w.\-/\\]+)")),
    ("long_literal", re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b")),
    ("code_block", re.compile(r"```|\bTraceback \(most recent call last\)|\bException:\s|\bError:\s")),
    ("redaction_placeholder", re.compile(r"<[A-Z_]+_\d+>")),
]

FORBIDDEN_EXPORT_KEYS = set([
    "sample_id",
    "request_id",
    "file_path_hash",
    "tenant_hash",
    "user_hash",
    "session_hash",
    "task_fingerprint_internal",
    "content_hash",
    "index_order",
    "source_id",
    "sampleId",
])


def infer_intent_label(canonical):
    text = last_user_content(canonical.get("request", {}).get("messages") or [])
    lowered = text.lower()
    if normalize_text(text) in GREETING_TEXTS or len(normalize_text(text)) <= 2:
        return "greeting_or_probe"
    if has_tool_interaction(canonical):
        return "use_tool"
    if any(token in lowered for token in ["bug", "报错", "traceback", "修复", "debug"]):
        return "debug_code"
    if any(token in lowered for token in ["python", "代码", "函数", "sql", "shell", "脚本"]):
        return "write_code"
    if any(token in lowered for token in ["总结", "改写", "翻译", "提取"]):
        return "summarize_or_transform"
    if any(token in lowered for token in ["推理", "证明", "分析", "为什么", "步骤"]):
        return "analyze_reason"
    if any(token in lowered for token in ["账单", "订单", "用户资料", "营业", "发票"]):
        return "domain_lookup"
    if text:
        return "answer_question"
    return "unknown"


def task_fingerprint_internal(canonical):
    payload = {
        "route": canonical.get("routing", {}).get("rule_label") or classify_by_rules(canonical),
        "intent": infer_intent_label(canonical),
        "user": normalize_text(last_user_content(canonical.get("request", {}).get("messages") or [])),
        "tools": sorted(tool_name_set(canonical)),
    }
    return content_hash(payload)[:24]


def task_bucket_for(canonical, selection_hmac_key=None):
    route = canonical.get("routing", {}).get("rule_label") or classify_by_rules(canonical)
    intent = infer_intent_label(canonical)
    coarse = "%s:%s" % (route, intent)
    if not selection_hmac_key:
        return coarse
    date = canonical.get("source", {}).get("date", "")
    internal = task_fingerprint_internal(canonical)
    digest = hmac_digest("%s:%s" % (date, internal), selection_hmac_key, 12)
    return "%s:%s" % (coarse, digest)


def tool_name_set(canonical):
    names = set()
    for tool in canonical.get("request", {}).get("tools") or []:
        if isinstance(tool, dict):
            fn = tool.get("function") or {}
            if isinstance(fn, dict) and isinstance(fn.get("name"), str):
                names.add(fn.get("name"))
    message = canonical.get("response", {}).get("message") or {}
    for call in message.get("tool_calls") or []:
        if isinstance(call, dict):
            fn = call.get("function") or {}
            if isinstance(fn, dict) and isinstance(fn.get("name"), str):
                names.add(fn.get("name"))
    return names


def default_selection_config(**overrides):
    config = {
        "selected_min_score": 0.6,
        "router_min_score": 0.5,
        "sft_min_score": 0.6,
        "tool_use_min_score": 0.6,
        "multi_turn_min_score": 0.6,
        "max_selected_sft_per_user_per_day": 1000,
        "max_selected_router_per_user_per_day": 2000,
        "max_selected_tool_use_per_user_per_day": 1000,
        "max_selected_per_task_fingerprint_per_day": 200,
        "max_high_value_per_task_fingerprint_per_day": 50,
        "label_max_input_chars": 1200,
        "max_in_memory_samples": DEFAULT_MAX_IN_MEMORY_SAMPLES,
        "max_selection_memory_mb": DEFAULT_MAX_SELECTION_MEMORY_MB,
        "max_episode_gap_minutes": 30,
        "selection_mode": "auto",
        "k_threshold": DEFAULT_K_THRESHOLD,
        "enable_route_labeler": False,
        "enable_quality_labeler": False,
        "enable_label_snippets": False,
        "disable_selection": False,
        "disable_episodes": False,
        "disable_diagnostics": False,
        "compat_output_set": False,
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
        "selection_hmac_key": os.environ.get("AUDIT_SELECTION_HMAC_KEY", ""),
    }
    for key, value in overrides.items():
        if value is not None:
            config[key] = value
    return config


def deterministic_quality(canonical, config):
    text = last_user_content(canonical.get("request", {}).get("messages") or [])
    response_text = extract_text_content(canonical.get("response", {}).get("message", {}).get("content"))
    normalized = normalize_text(text)
    route = canonical.get("routing", {}).get("rule_label") or classify_by_rules(canonical)
    intent = infer_intent_label(canonical)
    score = 0.5
    value_labels = []
    risk_labels = []
    reject_reasons = []
    if route == "code_generation" or intent in ("write_code", "debug_code"):
        score += 0.25
        value_labels.append("code_task")
    if route == "tool_agent" or intent == "use_tool":
        score += 0.25
        value_labels.append("tool_task")
    if route == "reasoning" or intent == "analyze_reason":
        score += 0.2
        value_labels.append("reasoning_task")
    if route == "domain_qa" or intent == "domain_lookup":
        score += 0.15
        value_labels.append("domain_task")
    if response_text and len(response_text) >= 8:
        score += 0.1
        value_labels.append("well_formed_response")
    if not text:
        score = 0.0
        reject_reasons.append("empty_user_text")
        risk_labels.append("low_information")
    elif normalized in GREETING_TEXTS or (len(normalized) <= 2 and route == "general_chat"):
        score = min(score, 0.2)
        reject_reasons.append("greeting_or_probe")
        risk_labels.append("low_information")
    elif len(normalized) < 4 and route == "general_chat":
        score = min(score, 0.3)
        reject_reasons.append("too_short_low_information")
        risk_labels.append("low_information")
    if canonical.get("response", {}).get("finish_reason") == "length":
        score = min(score, 0.4)
        reject_reasons.append("length_finish")
        risk_labels.append("length_finish")
    if count_redaction_hits(canonical.get("quality", {}).get("redaction_stats", {})):
        score = min(score, 0.45)
        reject_reasons.append("redaction_risk")
        risk_labels.append("redaction_risk")
    score = max(0.0, min(1.0, score))
    return score, sorted(set(value_labels)), sorted(set(risk_labels)), reject_reasons


def annotate_task_and_quality(canonical, config=None):
    if config is None:
        config = default_selection_config()
    route = classify_by_rules(canonical)
    intent = infer_intent_label(canonical)
    canonical.setdefault("routing", {})["rule_label"] = route
    canonical["task"] = {
        "route_label": route,
        "intent_label": intent,
        "task_fingerprint_internal": task_fingerprint_internal(canonical),
        "task_bucket": task_bucket_for(canonical, config.get("selection_hmac_key")),
        "episode_id_internal": canonical.get("task", {}).get("episode_id_internal"),
        "turn_index": canonical.get("task", {}).get("turn_index", 0),
    }
    deterministic_score, value_labels, risk_labels, reject_reasons = deterministic_quality(canonical, config)
    quality = canonical.setdefault("quality", {})
    existing_rejects = list(quality.get("reject_reasons") or [])
    for reason in reject_reasons:
        if reason not in existing_rejects:
            existing_rejects.append(reason)
    quality.update({
        "schema_version": QUALITY_SCHEMA_VERSION,
        "deterministic_quality_score": deterministic_score,
        "model_quality_score": quality.get("model_quality_score"),
        "final_quality_score": min(deterministic_score, float(quality.get("model_quality_score", deterministic_score) or deterministic_score)) if quality.get("model_quality_score") is not None else deterministic_score,
        "value_labels": sorted(set((quality.get("value_labels") or []) + value_labels)),
        "risk_labels": sorted(set((quality.get("risk_labels") or []) + risk_labels)),
        "reject_reasons": existing_rejects,
        "use_for": [],
        "score_bucket": score_bucket(deterministic_score),
    })
    if not existing_rejects and deterministic_score >= config.get("selected_min_score", 0.6):
        if deterministic_score >= config.get("router_min_score", 0.5):
            quality["use_for"].append("router_classification")
        if deterministic_score >= config.get("sft_min_score", 0.6) and export_sft(canonical) is not None:
            quality["use_for"].append("sft")
        if has_tool_interaction(canonical) and deterministic_score >= config.get("tool_use_min_score", 0.6) and export_selected_tool_use_sft(canonical, validate_only=True) is not None:
            quality["use_for"].append("tool_use_sft")
    return canonical


def refresh_selection_use_for(canonical, config):
    quality = canonical.setdefault("quality", {})
    original_rejects = quality.get("reject_reasons") or []
    score = quality.get("final_quality_score")
    if score is None:
        score = quality.get("deterministic_quality_score") or 0.0
    quality["use_for"] = []
    deterministic_score = quality.get("deterministic_quality_score") or 0.0
    if original_rejects or deterministic_score < config.get("selected_min_score", 0.6) or score < config.get("selected_min_score", 0.6):
        return canonical
    if score >= config.get("router_min_score", 0.5):
        quality["use_for"].append("router_classification")
    if score >= config.get("sft_min_score", 0.6) and export_sft(canonical) is not None:
        quality["use_for"].append("sft")
    if has_tool_interaction(canonical) and score >= config.get("tool_use_min_score", 0.6) and export_selected_tool_use_sft(canonical, validate_only=True) is not None:
        quality["use_for"].append("tool_use_sft")
    return canonical


def selected_base_metadata(canonical):
    return {
        "source_date": canonical.get("source", {}).get("date"),
        "route_label": canonical.get("task", {}).get("route_label"),
        "intent_label": canonical.get("task", {}).get("intent_label"),
        "score_bucket": canonical.get("quality", {}).get("score_bucket"),
        "value_labels": canonical.get("quality", {}).get("value_labels") or [],
        "risk_labels": canonical.get("quality", {}).get("risk_labels") or [],
        "model_bucket": model_bucket(canonical.get("request", {}).get("model")),
    }


def leakage_scan_text(text, max_chars=1200):
    if text is None:
        return True, None
    text = str(text)
    if len(text) > max_chars:
        return False, "too_long"
    stripped = text.strip()
    if not stripped:
        return False, "empty"
    for name, pattern in LEAKAGE_PATTERNS:
        if pattern.search(text):
            return False, name
    codeish = len(re.findall(r"[{};=]|\b(def|class|import|SELECT|function|const|var)\b", text))
    if codeish >= 12:
        return False, "code_heavy"
    if stripped.startswith("<") and stripped.endswith(">"):
        return False, "placeholder_only"
    return True, None


def verify_export_safe_value(value, max_chars=1200):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN_EXPORT_KEYS:
                raise ValueError("forbidden export key: %s" % key)
            lower_key = key.lower()
            if any(token in lower_key for token in ["hash", "fingerprint", "requestid", "sampleid"]):
                raise ValueError("forbidden export key: %s" % key)
            verify_export_safe_value(item, max_chars=max_chars)
    elif isinstance(value, list):
        for item in value:
            verify_export_safe_value(item, max_chars=max_chars)
    elif isinstance(value, str):
        if value == "":
            return
        ok, reason = leakage_scan_text(value, max_chars=max_chars)
        if not ok:
            raise ValueError("unsafe export value: %s" % reason)


def export_selected_sft(canonical):
    if "sft" not in canonical.get("quality", {}).get("use_for", []):
        return None
    legacy = export_sft(canonical)
    if legacy is None:
        return None
    record = {
        "schema_version": SELECTED_SCHEMA_VERSION,
        "instruction": legacy.get("instruction", ""),
        "input": legacy.get("input", ""),
        "output": legacy.get("output", ""),
        "messages": legacy.get("messages") or [],
        "metadata": selected_base_metadata(canonical),
    }
    verify_export_safe_value(record)
    return record


def selected_router_features(canonical):
    usage = canonical.get("response", {}).get("usage") or {}
    messages = canonical.get("request", {}).get("messages") or []
    return {
        "message_count": len(messages),
        "has_tools": has_tool_interaction(canonical),
        "prompt_tokens_bucket": token_bucket(usage.get("prompt_tokens", 0)),
        "completion_tokens_bucket": token_bucket(usage.get("completion_tokens", 0)),
        "client_type_bucket": client_type_bucket(canonical.get("request", {}).get("params", {}).get("client_type", "")),
        "route_label": canonical.get("task", {}).get("route_label"),
        "intent_label": canonical.get("task", {}).get("intent_label"),
        "model_bucket": model_bucket(canonical.get("request", {}).get("model")),
    }


def export_selected_router(canonical):
    if "router_classification" not in canonical.get("quality", {}).get("use_for", []):
        return None
    input_text = last_user_content(canonical.get("request", {}).get("messages") or [])
    record = {
        "schema_version": SELECTED_SCHEMA_VERSION,
        "input": input_text,
        "features": selected_router_features(canonical),
        "labels": {
            "final_label": final_route_label(canonical)[0],
            "rule_label": canonical.get("routing", {}).get("rule_label") or classify_by_rules(canonical),
        },
        "metadata": selected_base_metadata(canonical),
    }
    verify_export_safe_value(record)
    return record


def parse_tool_arguments_object(arguments):
    if not isinstance(arguments, str):
        return None
    try:
        parsed = json.loads(arguments or "{}")
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def validate_selected_tool_trace(canonical):
    tools = canonical.get("request", {}).get("tools") or []
    defined_names = set()
    for tool in tools:
        if not isinstance(tool, dict) or tool.get("type") != "function":
            return False, "invalid_tool_definition"
        fn = tool.get("function") or {}
        if not isinstance(fn, dict) or not isinstance(fn.get("name"), str) or not fn.get("name"):
            return False, "invalid_tool_definition"
        defined_names.add(fn.get("name"))

    def validate_call(call):
        if not valid_tool_call(call):
            return None, "invalid_tool_call"
        fn = call.get("function") or {}
        name = fn.get("name")
        if defined_names and name not in defined_names:
            return None, "unknown_tool_name"
        if parse_tool_arguments_object(fn.get("arguments")) is None:
            return None, "invalid_tool_arguments"
        return call.get("id"), None

    seen_call_ids = set()
    pending_call_ids = set()
    for message in canonical.get("request", {}).get("messages") or []:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        history_calls = message.get("tool_calls") or []
        if role == "assistant" and history_calls:
            if pending_call_ids:
                return False, "missing_tool_result"
            if not isinstance(history_calls, list):
                return False, "invalid_tool_call"
            for call in history_calls:
                call_id, reason = validate_call(call)
                if reason is not None:
                    return False, reason
                if call_id in seen_call_ids or call_id in pending_call_ids:
                    return False, "duplicate_tool_call_id"
                seen_call_ids.add(call_id)
                pending_call_ids.add(call_id)
        elif role == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or not call_id or call_id not in pending_call_ids:
                return False, "unmatched_tool_result"
            pending_call_ids.remove(call_id)
        elif pending_call_ids:
            return False, "missing_tool_result"
    if pending_call_ids:
        return False, "missing_tool_result"

    response_message = canonical.get("response", {}).get("message") or {}
    calls = response_message.get("tool_calls") or []
    if not calls:
        return False, "missing_tool_calls"
    if not isinstance(calls, list):
        return False, "invalid_tool_call"
    for call in calls:
        call_id, reason = validate_call(call)
        if reason is not None:
            return False, reason
        if call_id in seen_call_ids:
            return False, "duplicate_tool_call_id"
        seen_call_ids.add(call_id)
    return True, None

def export_selected_tool_use_sft(canonical, validate_only=False):
    ok, reason = validate_selected_tool_trace(canonical)
    if not ok:
        rejects = canonical.setdefault("quality", {}).setdefault("reject_reasons", [])
        if "invalid_selected_tool_trace" not in rejects:
            rejects.append("invalid_selected_tool_trace")
        risks = canonical.setdefault("quality", {}).setdefault("risk_labels", [])
        if "invalid_selected_tool_trace" not in risks:
            risks.append("invalid_selected_tool_trace")
        return None
    if validate_only:
        return {"ok": True}
    if "tool_use_sft" not in canonical.get("quality", {}).get("use_for", []):
        return None
    record = {
        "schema_version": SELECTED_SCHEMA_VERSION,
        "messages": canonical.get("request", {}).get("messages") or [],
        "tools": canonical.get("request", {}).get("tools") or [],
        "response_message": canonical.get("response", {}).get("message") or {},
        "metadata": selected_base_metadata(canonical),
    }
    verify_export_safe_value(record)
    return record


def extract_text_content(content):
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                if part.get("type") in (None, "text"):
                    text = part["text"].strip()
                    if text:
                        parts.append(text)
            elif isinstance(part, str):
                text = part.strip()
                if text:
                    parts.append(text)
        return "\n".join(parts)
    return ""


def last_user_content(messages):
    for message in reversed(messages):
        if not isinstance(message, dict):
            continue
        if message.get("role") == "user":
            return extract_text_content(message.get("content"))
    return ""


def export_text_messages(messages):
    exported = []
    has_user_text = False
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        if not isinstance(role, str):
            continue
        content = extract_text_content(message.get("content"))
        if not content:
            continue
        if role == "user":
            has_user_text = True
        exported.append({"role": role, "content": content})
    if not has_user_text:
        return None
    return exported


def has_tool_interaction(canonical):
    return bool(
        canonical["request"].get("tools")
        or canonical["response"]["message"].get("tool_calls")
    )


def classify_by_rules(canonical):
    request = canonical["request"]
    usage = canonical["response"].get("usage") or {}
    text = last_user_content(request.get("messages") or [])
    lowered = text.lower()
    if has_tool_interaction(canonical):
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


def normalize_model_label(model_label):
    if not isinstance(model_label, dict):
        return None
    label = model_label.get("label")
    confidence = model_label.get("confidence")
    if not (
        isinstance(label, str)
        and label in ROUTE_LABELS
        and isinstance(confidence, (int, float))
        and not isinstance(confidence, bool)
    ):
        return None
    confidence = float(confidence)
    if not math.isfinite(confidence) or confidence < 0.0 or confidence > 1.0:
        return None
    return {"label": label, "confidence": confidence}



def clamped_int(value, default, minimum, maximum):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return min(maximum, max(minimum, parsed))


def load_label_config(env=None):
    source = os.environ if env is None else env
    base_url = source.get("AUDIT_LABEL_BASE_URL", "").rstrip("/")
    api_key = source.get("AUDIT_LABEL_API_KEY", "")
    model = source.get("AUDIT_LABEL_MODEL", "")
    timeout = clamped_int(source.get("AUDIT_LABEL_TIMEOUT", "30"), 30, 1, 120)
    return {
        "enabled": bool(base_url and api_key and model),
        "base_url": base_url,
        "api_key": api_key,
        "model": model,
        "timeout": timeout,
    }


def parse_label_response(text):
    try:
        payload = json.loads(text)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    normalized = normalize_model_label(payload)
    if normalized is None:
        return None
    reason = payload.get("reason", "")
    if not isinstance(reason, str):
        return None
    return {
        "label": normalized["label"],
        "confidence": normalized["confidence"],
        "reason": reason,
    }


def label_content_from_response(payload):
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


def build_route_label_payload(canonical, allow_snippets=False, max_chars=1200):
    payload = {
        "task": "classify_route",
        "labels": sorted(ROUTE_LABELS),
        "sample": {
            "features": selected_router_features(canonical),
        },
        "response_format": {
            "label": "string",
            "confidence": "number",
            "reason": "string",
        },
    }
    if allow_snippets:
        text = last_user_content(canonical.get("request", {}).get("messages") or [])
        ok, reason = leakage_scan_text(text, max_chars=max_chars)
        if not ok:
            return payload, reason
        payload["sample"]["snippet"] = text[:max_chars]
    try:
        verify_export_safe_value(payload, max_chars=max_chars)
    except ValueError as exc:
        return payload, str(exc)
    return payload, None


def build_quality_label_payload(canonical, allow_snippets=False, max_chars=1200):
    usage = canonical.get("response", {}).get("usage") or {}
    payload = {
        "task": "score_quality",
        "allowed_intent_labels": sorted(INTENT_LABELS),
        "allowed_value_labels": sorted(VALUE_LABELS),
        "allowed_risk_labels": sorted(RISK_LABELS),
        "sample": {
            "features": {
                "route_label": canonical.get("task", {}).get("route_label"),
                "intent_label": canonical.get("task", {}).get("intent_label"),
                "has_tools": has_tool_interaction(canonical),
                "message_count": len(canonical.get("request", {}).get("messages") or []),
                "prompt_tokens_bucket": token_bucket(usage.get("prompt_tokens", 0)),
                "completion_tokens_bucket": token_bucket(usage.get("completion_tokens", 0)),
                "redaction_density_bucket": "has_redactions" if count_redaction_hits(canonical.get("quality", {}).get("redaction_stats", {})) else "none",
                "model_bucket": model_bucket(canonical.get("request", {}).get("model")),
            }
        },
        "response_format": {
            "quality_score": "number",
            "value_labels": "array[string]",
            "risk_labels": "array[string]",
            "reason": "string",
        },
    }
    if allow_snippets:
        user_text = last_user_content(canonical.get("request", {}).get("messages") or [])
        assistant_text = extract_text_content(canonical.get("response", {}).get("message", {}).get("content"))
        for name, snippet in (("user_snippet", user_text), ("assistant_snippet", assistant_text)):
            ok, reason = leakage_scan_text(snippet, max_chars=max_chars)
            if not ok:
                return payload, reason
            payload["sample"][name] = snippet[:max_chars]
    try:
        verify_export_safe_value(payload, max_chars=max_chars)
    except ValueError as exc:
        return payload, str(exc)
    return payload, None


def parse_quality_label_response(text):
    try:
        payload = json.loads(text)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    score = payload.get("quality_score")
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        return None
    score = float(score)
    if not math.isfinite(score) or score < 0.0 or score > 1.0:
        return None
    value_labels = payload.get("value_labels", [])
    risk_labels = payload.get("risk_labels", [])
    if not isinstance(value_labels, list) or not isinstance(risk_labels, list):
        return None
    clean_values = []
    clean_risks = []
    for label in value_labels:
        if isinstance(label, str) and label in VALUE_LABELS:
            clean_values.append(label)
    for label in risk_labels:
        if isinstance(label, str) and label in RISK_LABELS:
            clean_risks.append(label)
    reason = payload.get("reason", "")
    if not isinstance(reason, str):
        return None
    return {
        "quality_score": score,
        "value_labels": sorted(set(clean_values)),
        "risk_labels": sorted(set(clean_risks)),
        "reason": reason,
    }


def call_label_model(label_payload, config, urlopen=None, parser=parse_label_response):
    if not config.get("enabled"):
        return None, "labeler_disabled"
    try:
        verify_export_safe_value(label_payload, max_chars=config.get("max_input_chars", 1200))
    except ValueError:
        return None, "labeler_payload_unsafe"
    body = json.dumps(
        {
            "model": config["model"],
            "messages": [
                {
                    "role": "system",
                    "content": "Return only JSON for audit label classification.",
                },
                {"role": "user", "content": json.dumps(label_payload, ensure_ascii=False)},
            ],
            "temperature": 0,
        }
    ).encode("utf-8")
    opener = urlopen or urllib.request.urlopen
    try:
        request = urllib.request.Request(
            config["base_url"] + "/chat/completions",
            data=body,
            headers={
                "Authorization": "Bearer " + config["api_key"],
                "Content-Type": "application/json",
            },
        )
        with opener(request, timeout=config["timeout"]) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        return None, "labeler_request_failed:%s" % exc.__class__.__name__
    content = label_content_from_response(payload)
    if content is None:
        return None, "labeler_invalid_response"
    parsed = parser(content)
    if parsed is None:
        return None, "labeler_invalid_response"
    return parsed, None


def final_route_label(canonical):
    model_label = normalize_model_label(canonical["routing"].get("model_label"))
    if model_label:
        if model_label["confidence"] >= 0.75:
            return model_label["label"], "high"
        return model_label["label"], "low"
    rule_label = classify_by_rules(canonical)
    if rule_label in ROUTE_LABELS:
        return rule_label, "medium"
    return "unknown", "low"


def export_sft(canonical):
    message = canonical["response"]["message"]
    content = extract_text_content(message.get("content"))
    request_messages = export_text_messages(canonical["request"]["messages"])
    if (
        not content
        or request_messages is None
        or has_tool_interaction(canonical)
        or canonical["response"].get("finish_reason") == "length"
    ):
        return None
    return {
        "sample_id": canonical["sample_id"],
        "instruction": "",
        "input": last_user_content(canonical["request"]["messages"]),
        "output": content,
        "messages": request_messages + [{"role": "assistant", "content": content}],
        "metadata": {
            "source_date": canonical["source"]["date"],
            "model": canonical["request"].get("model"),
        },
    }


def export_tool_use_sft(canonical):
    if canonical["response"].get("finish_reason") == "length":
        return None
    if not has_tool_interaction(canonical):
        return None
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
            "has_tools": has_tool_interaction(canonical),
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "client_type": canonical["request"].get("params", {}).get("client_type", ""),
        },
        "labels": {
            "weak_model_label": canonical["routing"].get("weak_model_label"),
            "rule_label": rule_label,
            "model_label": normalize_model_label(canonical["routing"].get("model_label")),
            "final_label": final_label,
            "confidence": confidence,
        },
    }


DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
JSONL_OUTPUTS = (
    "canonical/%s.jsonl",
    "sft/%s.jsonl",
    "tool_use_sft/%s.jsonl",
    "router_classification/%s.jsonl",
    "label_queue/%s.jsonl",
    "reports/%s.rejects.jsonl",
)
SELECTION_JSONL_OUTPUTS = (
    "quality/%s.jsonl",
    "episodes/%s.jsonl",
    "selected/sft/%s.jsonl",
    "selected/tool_use_sft/%s.jsonl",
    "selected/router_classification/%s.jsonl",
    "selected/multi_turn_sft/%s.jsonl",
)
LEGACY_JSON_REPORTS = (
    "reports/%s.stats.json",
    "manifests/%s.manifest.json",
)
SELECTION_JSON_REPORTS = (
    "reports/%s.quality_stats.json",
    "reports/%s.user_task_stats.json",
    "reports/%s.selection_manifest.json",
)


def enabled_jsonl_templates(config):
    if config.get("compat_output_set") or config.get("disable_selection"):
        return JSONL_OUTPUTS
    templates = list(JSONL_OUTPUTS)
    if config.get("disable_diagnostics"):
        templates = [template for template in templates if not template.startswith("canonical/")]
    for template in SELECTION_JSONL_OUTPUTS:
        if config.get("disable_diagnostics") and (template.startswith("quality/") or template.startswith("episodes/")):
            continue
        if config.get("disable_episodes") and (template.startswith("episodes/") or template.startswith("selected/multi_turn_sft/")):
            continue
        templates.append(template)
    return tuple(templates)


def enabled_json_report_templates(config):
    reports = list(LEGACY_JSON_REPORTS)
    if not config.get("compat_output_set") and not config.get("disable_selection"):
        reports.extend(SELECTION_JSON_REPORTS)
    return tuple(reports)


def enabled_output_relatives(date, config):
    paths = [template % date for template in enabled_jsonl_templates(config)]
    paths.extend(template % date for template in enabled_json_report_templates(config))
    return paths


def validate_date_string(date):
    if not isinstance(date, str) or DATE_PATTERN.match(date) is None:
        raise ValueError("date must be YYYY-MM-DD")
    try:
        datetime.datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise ValueError("date must be a valid YYYY-MM-DD date")
    return date


def validate_relative_path(relative):
    if not isinstance(relative, str) or not relative:
        raise ValueError("relative path must be a non-empty string")
    path = pathlib.PurePath(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("unsafe relative path: %s" % relative)
    return relative


def path_under(root, relative):
    validate_relative_path(relative)
    root = pathlib.Path(root).resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise ValueError("path escapes root: %s" % relative)
    return candidate


def lexical_path_under(root, relative):
    validate_relative_path(relative)
    root = pathlib.Path(root).resolve()
    candidate = pathlib.Path(root) / relative
    parent = candidate.parent
    if parent.exists() and parent.is_symlink():
        raise ValueError("unsafe symlink parent: %s" % parent)
    try:
        parent.resolve().relative_to(root)
    except ValueError:
        raise ValueError("path escapes root: %s" % relative)
    return candidate


def safe_remove_tree_leaf(path, root):
    root = pathlib.Path(root).resolve()
    path = pathlib.Path(path)
    parent = path.parent
    if parent.exists() and parent.is_symlink():
        raise ValueError("unsafe symlink parent: %s" % parent)
    try:
        parent.resolve().relative_to(root)
    except ValueError:
        raise ValueError("path parent escapes root: %s" % path)
    try:
        path.lstat()
    except OSError:
        return
    if os.path.islink(str(path)):
        raise ValueError("unsafe symlink temp path: %s" % path)
    if not path.is_dir():
        raise ValueError("unsafe non-directory temp path: %s" % path)
    shutil.rmtree(str(path))


def unsafe_detail_path_error(index_record):
    return {
        "request_id": index_record.get("request_id"),
        "file_path_hash": file_path_hash(index_record),
        "reason": "unsafe_detail_path",
    }


def write_jsonl(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            write_jsonl_record(handle, record)


def write_jsonl_record(handle, record):
    handle.write(
        json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
    )


def write_json_file(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False),
        encoding="utf-8",
    )


def build_stats(canonical_records, rejects):
    stats = init_stats()
    for canonical in canonical_records:
        update_stats_for_canonical(stats, canonical)
    for reject in rejects:
        update_stats_for_reject(stats, reject)
    return stats


def init_stats():
    return {
        "accepted": 0,
        "rejected": 0,
        "models": {},
        "finish_reasons": {},
        "task_types": {},
        "reject_reasons": {},
        "redaction_hits": {},
    }


def update_stats_for_canonical(stats, canonical):
    stats["accepted"] += 1
    model = canonical["request"].get("model") or "unknown"
    stats["models"][model] = stats["models"].get(model, 0) + 1
    finish_reason = canonical["response"].get("finish_reason") or "unknown"
    stats["finish_reasons"][finish_reason] = stats["finish_reasons"].get(finish_reason, 0) + 1
    for task_type in canonical["quality"].get("task_types", []):
        stats["task_types"][task_type] = stats["task_types"].get(task_type, 0) + 1
    for key, value in canonical["quality"].get("redaction_stats", {}).items():
        stats["redaction_hits"][key] = stats["redaction_hits"].get(key, 0) + value


def update_stats_for_reject(stats, reject):
    stats["rejected"] += 1
    reason = reject.get("reason", "unknown")
    stats["reject_reasons"][reason] = stats["reject_reasons"].get(reason, 0) + 1


def append_if_record(records, record):
    if record is not None:
        records.append(record)


def collect_outputs(date, canonical_records, rejects, label_queue, stats, manifest):
    validate_date_string(date)
    sft_records = []
    tool_records = []
    router_records = []
    for canonical in canonical_records:
        if "sft" in canonical["quality"].get("task_types", []):
            append_if_record(sft_records, export_sft(canonical))
        if "tool_use_sft" in canonical["quality"].get("task_types", []):
            append_if_record(tool_records, export_tool_use_sft(canonical))
        router_record = export_router(canonical)
        append_if_record(router_records, router_record)
        if router_record is not None and router_record["labels"].get("confidence") == "low":
            label_queue.append(build_label_queue_record(canonical, "low_confidence_route"))
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


def output_relative_paths(date, config=None):
    validate_date_string(date)
    if config is None:
        config = default_selection_config(disable_selection=True)
    return enabled_output_relatives(date, config)


def tmp_leaf_name(date, run_id=None, backup=False):
    validate_date_string(date)
    base = "%s.%s" % (date, run_id) if run_id else date
    if backup:
        return base + ".backup"
    return base


def prepare_tmp_roots(output_root, date, run_id=None):
    validate_date_string(date)
    output_root = pathlib.Path(output_root)
    tmp_root = lexical_path_under(output_root, ".tmp/%s" % tmp_leaf_name(date, run_id))
    backup_root = lexical_path_under(output_root, ".tmp/%s" % tmp_leaf_name(date, run_id, backup=True))
    safe_remove_tree_leaf(tmp_root, output_root)
    safe_remove_tree_leaf(backup_root, output_root)
    tmp_root.mkdir(parents=True)
    return output_root, tmp_root, backup_root


def cleanup_tmp_root(path, output_root):
    safe_remove_tree_leaf(path, output_root)


def is_rollback_failed_error(exc):
    return "rollback_failed" in str(exc)


def rollback_replacements(created_finals, backups):
    for final in reversed(created_finals):
        if final.exists():
            final.unlink()
    for final, backup in reversed(backups):
        if backup.exists():
            final.parent.mkdir(parents=True, exist_ok=True)
            os.replace(str(backup), str(final))


def commit_tmp_outputs(output_root, date, relative_paths, run_id=None):
    output_root = pathlib.Path(output_root)
    tmp_root = lexical_path_under(output_root, ".tmp/%s" % tmp_leaf_name(date, run_id))
    backup_root = lexical_path_under(output_root, ".tmp/%s" % tmp_leaf_name(date, run_id, backup=True))
    backups = []
    created_finals = []
    preserve_backup = False
    try:
        for relative in relative_paths:
            final = path_under(output_root, relative)
            temp_file = path_under(tmp_root, relative)
            backup_file = path_under(backup_root, relative)
            final.parent.mkdir(parents=True, exist_ok=True)
            if final.exists():
                backup_file.parent.mkdir(parents=True, exist_ok=True)
                os.replace(str(final), str(backup_file))
                backups.append((final, backup_file))
            else:
                created_finals.append(final)
            os.replace(str(temp_file), str(final))
    except Exception as commit_error:
        try:
            rollback_replacements(created_finals, backups)
        except Exception as rollback_error:
            preserve_backup = True
            raise RuntimeError(
                "rollback_failed: %s; original_error: %s"
                % (rollback_error, commit_error)
            )
        raise
    finally:
        cleanup_tmp_root(tmp_root, output_root)
        if not preserve_backup:
            cleanup_tmp_root(backup_root, output_root)


def write_outputs_atomically(output_root, date, outputs):
    output_root, tmp_root, backup_root = prepare_tmp_roots(output_root, date)
    relative_paths = []
    commit_started = False
    try:
        for relative, value in outputs.items():
            validate_relative_path(relative)
            relative_paths.append(relative)
            target = path_under(tmp_root, relative)
            if relative.endswith(".jsonl"):
                write_jsonl(target, value)
            else:
                write_json_file(target, value)
        commit_started = True
        commit_tmp_outputs(output_root, date, relative_paths)
    except Exception as exc:
        if not commit_started:
            cleanup_tmp_root(tmp_root, output_root)
            cleanup_tmp_root(backup_root, output_root)
        elif not is_rollback_failed_error(exc):
            cleanup_tmp_root(backup_root, output_root)
        raise


def open_stream_writers(tmp_root, date, templates=None):
    handles = {}
    if templates is None:
        templates = JSONL_OUTPUTS
    try:
        for relative in [template % date for template in templates]:
            path = path_under(tmp_root, relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            handles[relative] = path.open("w", encoding="utf-8")
    except Exception:
        close_stream_writers(handles)
        raise
    return handles


def close_stream_writers(handles):
    first_error = None
    for handle in handles.values():
        try:
            handle.close()
        except Exception as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


def write_stream_record(handles, relative, record):
    if record is not None and relative in handles:
        write_jsonl_record(handles[relative], record)


def build_label_queue_record(canonical, reason, queue_id=None):
    record = {
        "schema_version": LABEL_QUEUE_SCHEMA_VERSION,
        "reason": reason,
        "features": selected_router_features(canonical),
        "labels": {
            "route_label": canonical.get("task", {}).get("route_label") or classify_by_rules(canonical),
            "intent_label": canonical.get("task", {}).get("intent_label") or infer_intent_label(canonical),
            "confidence": final_route_label(canonical)[1],
        },
    }
    if queue_id:
        record["queue_id"] = queue_id
    verify_export_safe_value(record)
    return record


def apply_optional_model_label(canonical, label_config, enable_route_labeler=False, enable_label_snippets=False, max_chars=1200):
    if not enable_route_labeler or not label_config.get("enabled"):
        return
    payload, error = build_route_label_payload(
        canonical,
        allow_snippets=enable_label_snippets,
        max_chars=max_chars,
    )
    if error is not None:
        canonical.setdefault("routing", {})["model_label_error"] = "payload_skipped"
        return
    model_label, _error = call_label_model(payload, label_config)
    normalized = normalize_model_label(model_label)
    if normalized is not None:
        canonical["routing"]["model_label"] = normalized


def apply_optional_quality_label(canonical, label_config, enable_quality_labeler=False, enable_label_snippets=False, max_chars=1200):
    if not enable_quality_labeler or not label_config.get("enabled"):
        return
    payload, error = build_quality_label_payload(
        canonical,
        allow_snippets=enable_label_snippets,
        max_chars=max_chars,
    )
    if error is not None:
        canonical.setdefault("quality", {})["model_quality_error"] = "payload_skipped"
        return
    parsed, _error = call_label_model(payload, label_config, parser=parse_quality_label_response)
    if parsed is None:
        return
    quality = canonical.setdefault("quality", {})
    deterministic = quality.get("deterministic_quality_score")
    quality["model_quality_score"] = parsed["quality_score"]
    quality["model_value_labels"] = parsed["value_labels"]
    quality["model_risk_labels"] = parsed["risk_labels"]
    quality["model_quality_reason_code"] = "model_suggestion"
    existing_values = set(quality.get("value_labels") or [])
    existing_risks = set(quality.get("risk_labels") or [])
    existing_values.update(parsed["value_labels"])
    existing_risks.update(parsed["risk_labels"])
    quality["value_labels"] = sorted(existing_values)
    quality["risk_labels"] = sorted(existing_risks)
    if parsed["risk_labels"]:
        rejects = quality.setdefault("reject_reasons", [])
        if "model_risk" not in rejects:
            rejects.append("model_risk")
    if deterministic is not None and parsed["quality_score"] < deterministic:
        quality["final_quality_score"] = parsed["quality_score"]
        if parsed["quality_score"] < 0.6:
            rejects = quality.setdefault("reject_reasons", [])
            if "model_downranked" not in rejects:
                rejects.append("model_downranked")
    elif deterministic is not None:
        quality["final_quality_score"] = deterministic


def write_canonical_exports(handles, date, canonical):
    write_stream_record(handles, "canonical/%s.jsonl" % date, canonical)
    if "sft" in canonical["quality"].get("task_types", []):
        write_stream_record(handles, "sft/%s.jsonl" % date, export_sft(canonical))
    if "tool_use_sft" in canonical["quality"].get("task_types", []):
        write_stream_record(
            handles,
            "tool_use_sft/%s.jsonl" % date,
            export_tool_use_sft(canonical),
        )
    router_record = export_router(canonical)
    write_stream_record(handles, "router_classification/%s.jsonl" % date, router_record)
    if router_record is not None and router_record["labels"].get("confidence") == "low":
        write_stream_record(
            handles,
            "label_queue/%s.jsonl" % date,
            build_label_queue_record(canonical, "low_confidence_route"),
        )


def quality_export_record(canonical):
    quality = canonical.get("quality", {})
    record = {
        "schema_version": QUALITY_SCHEMA_VERSION,
        "sample_id": canonical.get("sample_id"),
        "source_date": canonical.get("source", {}).get("date"),
        "task": copy.deepcopy(canonical.get("task", {})),
        "quality": {
            "deterministic_quality_score": quality.get("deterministic_quality_score"),
            "model_quality_score": quality.get("model_quality_score"),
            "final_quality_score": quality.get("final_quality_score"),
            "score_bucket": quality.get("score_bucket"),
            "value_labels": quality.get("value_labels") or [],
            "risk_labels": quality.get("risk_labels") or [],
            "reject_reasons": quality.get("reject_reasons") or [],
            "use_for": quality.get("use_for") or [],
        },
        "features": {
            "route_label": canonical.get("task", {}).get("route_label"),
            "intent_label": canonical.get("task", {}).get("intent_label"),
            "has_tools": has_tool_interaction(canonical),
            "model_bucket": model_bucket(canonical.get("request", {}).get("model")),
        },
    }
    record["reject_reasons"] = record["quality"]["reject_reasons"]
    return record



def episode_sort_key(canonical):
    source = canonical.get("source", {})
    return (
        source.get("date") or "",
        source.get("user_hash") or "",
        source.get("session_hash") or "",
        source.get("event_time_ms") is None,
        source.get("event_time_ms") or 0,
        source.get("index_order") or [],
        canonical.get("sample_id") or "",
    )


def same_episode(previous, current, config=None):
    if config is None:
        config = {}
    previous_source = previous.get("source", {})
    current_source = current.get("source", {})
    previous_time = previous_source.get("event_time_ms")
    current_time = current_source.get("event_time_ms")
    if previous_time is None or current_time is None:
        return False
    if previous_source.get("date") != current_source.get("date"):
        return False
    previous_user = previous_source.get("user_hash")
    current_user = current_source.get("user_hash")
    if not previous_user or previous_user != current_user:
        return False
    previous_session = previous_source.get("session_hash")
    current_session = current_source.get("session_hash")
    if not previous_session or not current_session or previous_session != current_session:
        return False
    max_gap_minutes = config.get("max_episode_gap_minutes", 30)
    try:
        max_gap_ms = int(max_gap_minutes) * 60 * 1000
    except (TypeError, ValueError):
        max_gap_ms = 30 * 60 * 1000
    return abs(int(current_time) - int(previous_time)) <= max_gap_ms


def build_episode_record(records):
    source_date = records[0].get("source", {}).get("date") if records else None
    route_labels = [record.get("task", {}).get("route_label") for record in records]
    intent_labels = [record.get("task", {}).get("intent_label") for record in records]
    route_label = route_labels[0] if route_labels and all(label == route_labels[0] for label in route_labels) else "mixed"
    intent_label = intent_labels[0] if intent_labels and all(label == intent_labels[0] for label in intent_labels) else "mixed"
    event_times = [record.get("source", {}).get("event_time_ms") for record in records]
    missing_time = any(value is None for value in event_times)
    missing_session = any(not record.get("source", {}).get("session_hash") for record in records)
    turn_ids = [record.get("sample_id") for record in records]
    episode_id_internal = content_hash({"source_date": source_date, "turns": turn_ids})[:32]
    for index, record in enumerate(records):
        record.setdefault("task", {})["episode_id_internal"] = episode_id_internal
        record.setdefault("task", {})["turn_index"] = index
    min_score = min([
        record.get("quality", {}).get("final_quality_score") or 0.0
        for record in records
    ] or [0.0])
    eligible = (
        len(records) > 1
        and not missing_time
        and not missing_session
        and all(not record.get("quality", {}).get("reject_reasons") for record in records)
        and all((record.get("quality", {}).get("final_quality_score") or 0.0) >= 0.6 for record in records)
    )
    record = {
        "schema_version": EPISODE_SCHEMA_VERSION,
        "episode_id_internal": episode_id_internal,
        "source_date": source_date,
        "turn_count": len(records),
        "route_label": route_label,
        "intent_label": intent_label,
        "score_bucket": score_bucket(min_score),
        "missing_session_fallback": missing_session,
        "index_order_only": missing_time,
        "eligible_for_selected_multi_turn": eligible,
        "turns": [
            {
                "sample_id": item.get("sample_id"),
                "turn_index": index,
                "event_time_ms": item.get("source", {}).get("event_time_ms"),
                "index_order": item.get("source", {}).get("index_order") or [],
                "route_label": item.get("task", {}).get("route_label"),
                "intent_label": item.get("task", {}).get("intent_label"),
                "score_bucket": item.get("quality", {}).get("score_bucket"),
            }
            for index, item in enumerate(records)
        ],
    }
    return record


def build_episodes(annotated_records, config=None):
    if config is None:
        config = default_selection_config()
    episodes = []
    current = []
    for canonical in sorted(annotated_records, key=episode_sort_key):
        if not current:
            current.append(canonical)
        elif same_episode(current[-1], canonical, config):
            current.append(canonical)
        else:
            episodes.append(build_episode_record(current))
            current = [canonical]
    if current:
        episodes.append(build_episode_record(current))
    return episodes

def init_dedupe_state(config):
    return {
        "seen": {"router_classification": set(), "sft": set(), "tool_use_sft": set()},
        "normalized": {"router_classification": set(), "sft": set(), "tool_use_sft": set()},
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


def mark_dedupe_saturated(canonical, state):
    quality = canonical.setdefault("quality", {})
    risks = quality.setdefault("risk_labels", [])
    add_unique_list_value(risks, "dedupe_state_saturated")
    quality["risk_labels"] = sorted(set(risks))
    add_dedupe_risk(state, "dedupe_state_saturated")


def can_add_state_key(mapping, key, max_keys, canonical, state):
    if key in mapping:
        return True
    if len(mapping) < max_keys:
        return True
    mark_dedupe_saturated(canonical, state)
    return False


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


def mark_dedupe_suppression(canonical, state, reason, risk, kind):
    quality = canonical.setdefault("quality", {})
    dedupe = quality.setdefault("dedupe", {})
    add_unique_list_value(dedupe.setdefault("suppressed_use_for", []), kind)
    add_unique_list_value(dedupe.setdefault("matched_reasons", []), reason)
    dedupe["matched_reason"] = reason
    dedupe["decision"] = "suppressed"
    quality["use_for"] = [value for value in quality.get("use_for", []) if value != kind]
    add_unique_list_value(quality.setdefault("risk_labels", []), risk)
    add_dedupe_count(state, reason)
    add_dedupe_risk(state, risk)


def finalize_dedupe_suppression(canonical):
    quality = canonical.setdefault("quality", {})
    dedupe = quality.setdefault("dedupe", {})
    matched_reasons = dedupe.get("matched_reasons") or []
    if matched_reasons and not quality.get("use_for"):
        for reason in matched_reasons:
            add_unique_list_value(quality.setdefault("reject_reasons", []), reason)
        dedupe["decision"] = "rejected"


def apply_dedupe_annotation(canonical, config, state):
    quality = canonical.setdefault("quality", {})
    text = last_user_content(canonical.get("request", {}).get("messages") or [])
    normalized = normalize_for_dedupe(text)
    tokens = dedupe_tokens(text)
    simhash = simhash64(tokens)
    near_bucket = canonical.get("task", {}).get("task_bucket") or task_bucket_for(
        canonical, config.get("selection_hmac_key")
    )
    quality["dedupe"] = {
        "bucket": dedupe_bucket(canonical),
        "normalized_prompt_hash": content_hash(normalized)[:24],
        "simhash64": "%016x" % simhash,
        "token_count": len(tokens),
        "decision": "checked",
    }
    if not config.get("enable_dedupe", True) or quality.get("reject_reasons"):
        return canonical
    add_dedupe_count(state, "checked")
    if not config.get("enable_near_duplicate_dedupe", True):
        return canonical
    if len(normalized) < config.get("near_duplicate_min_chars", 16):
        return canonical
    if len(tokens) < config.get("near_duplicate_min_tokens", 4):
        return canonical
    representatives = state.setdefault("representatives", {})
    max_buckets = config.get("max_near_duplicate_buckets", 50000)
    if not can_add_state_key(representatives, near_bucket, max_buckets, canonical, state):
        return canonical
    bucket_representatives = representatives.setdefault(near_bucket, [])
    max_representatives = config.get("max_near_duplicate_representatives_per_bucket", 128)
    if len(bucket_representatives) >= max_representatives:
        mark_dedupe_saturated(canonical, state)
        return canonical
    bucket_representatives.append({
        "normalized": normalized,
        "tokens": tokens,
        "simhash": simhash,
    })
    return canonical


def apply_dedupe_annotations_to_records(annotated_records, config):
    state = init_dedupe_state(config)
    for canonical in sorted(annotated_records, key=selection_rank_key):
        refresh_selection_use_for(canonical, config)
        apply_dedupe_annotation(canonical, config, state)
    return state


def add_count(counter, key):
    counter[key] = counter.get(key, 0) + 1


def k_suppressed_counts(counter, k_threshold):
    visible = {}
    suppressed = 0
    for key, count in sorted(counter.items()):
        if count >= k_threshold:
            visible[key] = count
        else:
            suppressed += count
    if suppressed:
        visible["suppressed_small_count"] = suppressed
    return visible


def build_quality_stats(annotated_records, k_threshold=DEFAULT_K_THRESHOLD):
    state = init_selection_report_state()
    for canonical in annotated_records:
        update_selection_report_state(state, canonical)
    return quality_stats_from_state(state, k_threshold)


def build_user_task_stats(annotated_records, k_threshold=DEFAULT_K_THRESHOLD):
    state = init_selection_report_state()
    for canonical in annotated_records:
        update_selection_report_state(state, canonical)
    return user_task_stats_from_state(state, k_threshold)


def init_selection_report_state():
    return {
        "total": 0,
        "route_counts": {},
        "intent_counts": {},
        "score_counts": {},
        "combo_counts": {},
        "reject_counts": {},
        "user_task_buckets": {},
    }


def update_selection_report_state(state, canonical):
    state["total"] += 1
    task = canonical.get("task", {})
    quality = canonical.get("quality", {})
    route = task.get("route_label") or "unknown"
    intent = task.get("intent_label") or "unknown"
    score = quality.get("score_bucket") or "unknown"
    add_count(state["route_counts"], route)
    add_count(state["intent_counts"], intent)
    add_count(state["score_counts"], score)
    add_count(state["combo_counts"], "%s|%s|%s" % (route, intent, score))
    add_count(state["user_task_buckets"], "%s|%s|%s" % (route, intent, score))
    for reason in quality.get("reject_reasons") or []:
        add_count(state["reject_counts"], reason)


def quality_stats_from_state(state, k_threshold):
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "total": state.get("total", 0),
        "route_counts": k_suppressed_counts(state.get("route_counts", {}), k_threshold),
        "intent_counts": k_suppressed_counts(state.get("intent_counts", {}), k_threshold),
        "score_counts": k_suppressed_counts(state.get("score_counts", {}), k_threshold),
        "route_intent_score_counts": k_suppressed_counts(state.get("combo_counts", {}), k_threshold),
        "reject_reasons": k_suppressed_counts(state.get("reject_counts", {}), k_threshold),
        "k_threshold": k_threshold,
    }


def user_task_stats_from_state(state, k_threshold):
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "bucket_counts": k_suppressed_counts(state.get("user_task_buckets", {}), k_threshold),
        "k_threshold": k_threshold,
        "note": "Aggregated by non-linkable route/intent/score buckets; no user/session hashes emitted.",
    }



def export_selected_multi_turn_sft(episode, sample_by_id, config):
    if not episode.get("eligible_for_selected_multi_turn"):
        return None
    messages = []
    min_score = 1.0
    for turn in episode.get("turns") or []:
        canonical = sample_by_id.get(turn.get("sample_id"))
        if canonical is None:
            return None
        score = canonical.get("quality", {}).get("final_quality_score") or 0.0
        min_score = min(min_score, score)
        if score < config.get("multi_turn_min_score", 0.6) or canonical.get("quality", {}).get("reject_reasons"):
            return None
        user_text = last_user_content(canonical.get("request", {}).get("messages") or [])
        assistant_text = extract_text_content(canonical.get("response", {}).get("message", {}).get("content"))
        if not user_text or not assistant_text:
            return None
        messages.append({"role": "user", "content": user_text})
        messages.append({"role": "assistant", "content": assistant_text})
    record = {
        "schema_version": SELECTED_SCHEMA_VERSION,
        "episode_export_id": hmac_digest(episode.get("episode_id_internal"), str(uuid.uuid4()), 16),
        "messages": messages,
        "metadata": {
            "source_date": episode.get("source_date"),
            "turn_count": episode.get("turn_count"),
            "route_label": episode.get("route_label"),
            "intent_label": episode.get("intent_label"),
            "score_bucket": score_bucket(min_score),
        },
    }
    verify_export_safe_value(record)
    return record


def selected_duplicate_key(kind, canonical):
    text = normalize_text(last_user_content(canonical.get("request", {}).get("messages") or []))
    route = canonical.get("task", {}).get("route_label")
    intent = canonical.get("task", {}).get("intent_label")
    if kind == "sft":
        response = extract_text_content(canonical.get("response", {}).get("message", {}).get("content"))
        return content_hash({"text": text, "response": response, "route": route, "intent": intent})
    if kind == "tool_use_sft":
        return content_hash({"text": text, "tools": sorted(tool_name_set(canonical)), "route": route, "intent": intent})
    return content_hash({"text": text, "route": route, "intent": intent})


def selection_rank_key(canonical):
    quality = canonical.get("quality", {})
    source = canonical.get("source", {})
    value_priority = 1 if quality.get("value_labels") else 0
    return (
        -(quality.get("final_quality_score") or 0.0),
        -value_priority,
        source.get("event_time_ms") is None,
        source.get("event_time_ms") or 0,
        source.get("index_order") or [],
        canonical.get("sample_id") or "",
    )


def init_selected_export_state():
    return {
        "outputs": {"sft": [], "tool_use_sft": [], "router_classification": [], "multi_turn_sft": []},
        "seen": {"sft": set(), "tool_use_sft": set(), "router_classification": set()},
        "user_counts": {},
        "task_counts": {},
        "high_value_task_counts": {},
    }


def suppress_selected_duplicate(canonical, dedupe_state, reason, kind):
    if dedupe_state is None:
        quality = canonical.setdefault("quality", {})
        add_unique_list_value(quality.setdefault("risk_labels", []), "duplicate")
        return
    mark_dedupe_suppression(canonical, dedupe_state, reason, "duplicate", kind)
    finalize_dedupe_suppression(canonical)


def consider_selected_record(canonical, config, state, dedupe_state=None):
    quality = canonical.get("quality", {})
    if quality.get("reject_reasons"):
        return
    user_key = canonical.get("source", {}).get("user_hash") or "unknown"
    task_key = canonical.get("task", {}).get("task_fingerprint_internal") or "unknown"
    for kind, exporter, quota_key in (
        ("router_classification", export_selected_router, "max_selected_router_per_user_per_day"),
        ("sft", export_selected_sft, "max_selected_sft_per_user_per_day"),
        ("tool_use_sft", export_selected_tool_use_sft, "max_selected_tool_use_per_user_per_day"),
    ):
        if kind not in quality.get("use_for", []):
            continue
        user_count_key = "%s:%s" % (kind, user_key)
        task_count_key = "%s:%s" % (kind, task_key)
        if state["user_counts"].get(user_count_key, 0) >= config.get(quota_key, 1000):
            if "quota_exceeded" not in quality.setdefault("risk_labels", []):
                quality["risk_labels"].append("quota_exceeded")
            continue
        if state["task_counts"].get(task_count_key, 0) >= config.get("max_selected_per_task_fingerprint_per_day", 200):
            if "quota_exceeded" not in quality.setdefault("risk_labels", []):
                quality["risk_labels"].append("quota_exceeded")
            continue
        high_value_count_key = "%s:%s" % (kind, task_key)
        if quality.get("value_labels") and state["high_value_task_counts"].get(high_value_count_key, 0) >= config.get("max_high_value_per_task_fingerprint_per_day", 50):
            if "quota_exceeded" not in quality.setdefault("risk_labels", []):
                quality["risk_labels"].append("quota_exceeded")
            continue
        key = selected_duplicate_key(kind, canonical)
        normalized_key = dedupe_signature_for(kind, canonical)
        if key in state["seen"][kind]:
            suppress_selected_duplicate(canonical, dedupe_state, "duplicate_content", kind)
            continue
        if dedupe_state is not None and normalized_key in dedupe_state["normalized"][kind]:
            suppress_selected_duplicate(canonical, dedupe_state, "normalized_duplicate_content", kind)
            continue
        record = exporter(canonical)
        if record is None:
            continue
        state["outputs"][kind].append(record)
        state["seen"][kind].add(key)
        if dedupe_state is not None:
            normalized_seen = dedupe_state["normalized"][kind]
            if can_add_state_key(normalized_seen, normalized_key, dedupe_state.get("max_seen_hashes", 1000000), canonical, dedupe_state):
                normalized_seen.add(normalized_key)
        state["user_counts"][user_count_key] = state["user_counts"].get(user_count_key, 0) + 1
        state["task_counts"][task_count_key] = state["task_counts"].get(task_count_key, 0) + 1
        if quality.get("value_labels"):
            state["high_value_task_counts"][high_value_count_key] = state["high_value_task_counts"].get(high_value_count_key, 0) + 1


def build_selected_outputs(annotated_records, episodes, config):
    state = init_selected_export_state()
    dedupe_state = init_dedupe_state(config)
    for canonical in sorted(annotated_records, key=selection_rank_key):
        consider_selected_record(canonical, config, state, dedupe_state)
    sample_by_id = {canonical.get("sample_id"): canonical for canonical in annotated_records}
    if not config.get("disable_episodes"):
        for episode in episodes:
            record = export_selected_multi_turn_sft(episode, sample_by_id, config)
            if record is not None:
                state["outputs"]["multi_turn_sft"].append(record)
    return state["outputs"]


def iter_jsonl_records(path):
    with pathlib.Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def process_spooled_selection_records(spool_path, config, date, handles=None):
    report_state = init_selection_report_state()
    selected_state = init_selected_export_state()
    current_episode = []

    def flush_episode():
        if not current_episode:
            return
        if handles is not None and not config.get("disable_diagnostics") and not config.get("disable_episodes"):
            write_stream_record(handles, "episodes/%s.jsonl" % date, build_episode_record(current_episode))
        del current_episode[:]

    for canonical in iter_jsonl_records(spool_path):
        update_selection_report_state(report_state, canonical)
        consider_selected_record(canonical, config, selected_state)
        if handles is not None and not config.get("disable_diagnostics"):
            write_stream_record(handles, "quality/%s.jsonl" % date, quality_export_record(canonical))
        if not config.get("disable_episodes"):
            if not current_episode:
                current_episode.append(canonical)
            elif same_episode(current_episode[-1], canonical):
                current_episode.append(canonical)
            else:
                flush_episode()
                current_episode.append(canonical)
    flush_episode()
    return {
        "candidate_count": report_state["total"],
        "selected_outputs": selected_state["outputs"],
        "quality_stats": quality_stats_from_state(report_state, config.get("k_threshold", DEFAULT_K_THRESHOLD)),
        "user_task_stats": user_task_stats_from_state(report_state, config.get("k_threshold", DEFAULT_K_THRESHOLD)),
    }


def build_selection_manifest(
    date,
    config,
    mode_used,
    run_id,
    annotated_records,
    selected_outputs,
    started_at,
    finished_at,
    candidate_count=None,
):
    enabled = enabled_output_relatives(date, config)
    if candidate_count is None:
        candidate_count = len(annotated_records)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "date": date,
        "pipeline_version": PIPELINE_VERSION,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "sensitivity": {
            "canonical": "restricted_diagnostic",
            "quality": "restricted_diagnostic",
            "episodes": "restricted_diagnostic",
            "selected": "training_facing_privacy_strict",
            "reports": "operational_k_suppressed",
        },
        "schema_versions": {
            "canonical": CANONICAL_SCHEMA_VERSION,
            "quality": QUALITY_SCHEMA_VERSION,
            "episodes": EPISODE_SCHEMA_VERSION,
            "selected": SELECTED_SCHEMA_VERSION,
            "reports": REPORT_SCHEMA_VERSION,
            "label_queue": LABEL_QUEUE_SCHEMA_VERSION,
        },
        "output_matrix": {
            "enabled_outputs": sorted(set(path.rsplit("/", 1)[0] for path in enabled)),
            "relative_paths": enabled,
            "disable_selection": bool(config.get("disable_selection")),
            "disable_episodes": bool(config.get("disable_episodes")),
            "disable_diagnostics": bool(config.get("disable_diagnostics")),
            "compat_output_set": bool(config.get("compat_output_set")),
        },
        "selection": {
            "mode_used": mode_used,
            "selection_mode": config.get("selection_mode"),
            "max_in_memory_samples": config.get("max_in_memory_samples"),
            "max_selection_memory_mb": config.get("max_selection_memory_mb"),
            "selected_counts": {key: len(value) for key, value in selected_outputs.items()},
            "candidate_count": candidate_count,
        },
        "labelers": {
            "route_enabled": bool(config.get("enable_route_labeler")),
            "quality_enabled": bool(config.get("enable_quality_labeler")),
            "snippets_enabled": bool(config.get("enable_label_snippets")),
            "feature_only_default": not bool(config.get("enable_label_snippets")),
        },
        "k_threshold": config.get("k_threshold"),
    }


def process_is_alive(pid):
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError as exc:
        return exc.errno == errno.EPERM
    return True


def acquire_run_lock(output_root, date, run_id, ttl_seconds=DEFAULT_LOCK_TTL_SECONDS):
    output_root = pathlib.Path(output_root)
    lock_dir = lexical_path_under(output_root, ".tmp/locks")
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / (date + ".lock")
    metadata = {
        "pid": os.getpid(),
        "hostname": socket.gethostname(),
        "run_id": run_id,
        "date": date,
        "started_at_epoch": time.time(),
    }
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
        try:
            existing = json.loads(lock_path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
        age = time.time() - float(existing.get("started_at_epoch", 0) or 0)
        if (not existing.get("hostname") or existing.get("hostname") == socket.gethostname()) and process_is_alive(existing.get("pid")):
            raise RuntimeError("active lock exists for %s" % date)
        if age < ttl_seconds:
            raise RuntimeError("recent stale lock exists for %s" % date)
        try:
            lock_path.unlink()
        except OSError:
            raise RuntimeError("could not remove stale lock for %s" % date)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(metadata, ensure_ascii=False, sort_keys=True))
    return lock_path


def release_run_lock(lock_path, output_root, run_id=None):
    if lock_path is not None:
        try:
            path = pathlib.Path(lock_path)
            if run_id is not None:
                metadata = json.loads(path.read_text(encoding="utf-8"))
                if metadata.get("run_id") != run_id:
                    cleanup_empty_tmp_dirs(output_root)
                    return
            path.unlink()
        except OSError:
            pass
        except ValueError:
            pass
    cleanup_empty_tmp_dirs(output_root)


def cleanup_empty_tmp_dirs(output_root):
    tmp = pathlib.Path(output_root) / ".tmp"
    for child in (tmp / "locks", tmp):
        try:
            child.rmdir()
        except OSError:
            pass


def estimate_record_size(record):
    return len(json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False).encode("utf-8")) * 3


def should_spool_next(current_count, current_bytes, record, config):
    if config.get("selection_mode") == "spool":
        return True
    if config.get("selection_mode") == "in-memory":
        return False
    max_samples = config.get("max_in_memory_samples", DEFAULT_MAX_IN_MEMORY_SAMPLES)
    max_bytes = int(config.get("max_selection_memory_mb", DEFAULT_MAX_SELECTION_MEMORY_MB)) * 1024 * 1024
    return current_count >= max_samples or current_bytes + estimate_record_size(record) > max_bytes


def spool_path_for(output_root, date, run_id):
    return lexical_path_under(output_root, ".tmp/%s.%s/selection_spool/candidates.jsonl" % (date, run_id))


def cleanup_run_tmp(output_root, date, run_id):
    run_tmp = lexical_path_under(output_root, ".tmp/%s.%s" % (date, run_id))
    cleanup_tmp_root(run_tmp, output_root)
    cleanup_empty_tmp_dirs(output_root)


def reject_report_record(date, reject):
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "date": date,
        "reason": reject.get("reason", "unknown") if isinstance(reject, dict) else "unknown",
    }


def write_reject(handles, date, reject):
    write_stream_record(handles, "reports/%s.rejects.jsonl" % date, reject_report_record(date, reject))


def reject_json_constant(value):
    raise ValueError("non-standard JSON constant: %s" % value)


def load_audit_record(input_root, index_record):
    root = pathlib.Path(input_root).resolve()
    try:
        detail_path = path_under(root, index_record["file_path"])
    except (KeyError, ValueError):
        return None, unsafe_detail_path_error(index_record)
    if not detail_path.exists():
        return None, {
            "request_id": index_record.get("request_id"),
            "file_path_hash": file_path_hash(index_record),
            "reason": "missing_detail_file",
        }
    try:
        with detail_path.open("r", encoding="utf-8") as handle:
            return json.load(
                handle,
                parse_constant=reject_json_constant,
                parse_float=parse_finite_float,
            ), None
    except ValueError:
        return None, {
            "request_id": index_record.get("request_id"),
            "file_path_hash": file_path_hash(index_record),
            "reason": "bad_detail_json",
        }


def process_date(
    input_root,
    output_root,
    date,
    limit=None,
    dry_run=False,
    disable_selection=False,
    disable_episodes=False,
    disable_diagnostics=False,
    compat_output_set=False,
    enable_route_labeler=False,
    enable_quality_labeler=False,
    enable_label_snippets=False,
    selected_min_score=0.6,
    router_min_score=0.5,
    sft_min_score=0.6,
    tool_use_min_score=0.6,
    multi_turn_min_score=0.6,
    max_selected_sft_per_user_per_day=1000,
    max_selected_router_per_user_per_day=2000,
    max_selected_tool_use_per_user_per_day=1000,
    max_selected_per_task_fingerprint_per_day=200,
    max_high_value_per_task_fingerprint_per_day=50,
    label_max_input_chars=1200,
    max_in_memory_samples=DEFAULT_MAX_IN_MEMORY_SAMPLES,
    max_selection_memory_mb=DEFAULT_MAX_SELECTION_MEMORY_MB,
    selection_mode="auto",
    k_threshold=DEFAULT_K_THRESHOLD,
):
    validate_date_string(date)
    if selection_mode not in ("auto", "in-memory", "spool"):
        raise ValueError("selection_mode must be auto, in-memory, or spool")
    if compat_output_set:
        disable_selection = True
        disable_episodes = True
        disable_diagnostics = False
    config = default_selection_config(
        disable_selection=disable_selection,
        disable_episodes=disable_episodes,
        disable_diagnostics=disable_diagnostics,
        compat_output_set=compat_output_set,
        enable_route_labeler=enable_route_labeler,
        enable_quality_labeler=enable_quality_labeler,
        enable_label_snippets=enable_label_snippets,
        selected_min_score=selected_min_score,
        router_min_score=router_min_score,
        sft_min_score=sft_min_score,
        tool_use_min_score=tool_use_min_score,
        multi_turn_min_score=multi_turn_min_score,
        max_selected_sft_per_user_per_day=max_selected_sft_per_user_per_day,
        max_selected_router_per_user_per_day=max_selected_router_per_user_per_day,
        max_selected_tool_use_per_user_per_day=max_selected_tool_use_per_user_per_day,
        max_selected_per_task_fingerprint_per_day=max_selected_per_task_fingerprint_per_day,
        max_high_value_per_task_fingerprint_per_day=max_high_value_per_task_fingerprint_per_day,
        label_max_input_chars=label_max_input_chars,
        max_in_memory_samples=max_in_memory_samples,
        max_selection_memory_mb=max_selection_memory_mb,
        selection_mode=selection_mode,
        k_threshold=k_threshold,
    )
    selection_enabled = not config.get("disable_selection") and not config.get("compat_output_set")
    started_at = datetime.datetime.utcnow().isoformat() + "Z"
    output_root_path = pathlib.Path(output_root)
    run_id = uuid.uuid4().hex[:12]
    tmp_root = None
    backup_root = None
    lock_path = None
    handles = {}
    stats = init_stats()
    index_record_count = 0
    files_attempted = 0
    files_loaded = 0
    commit_started = False
    mode_used = "disabled" if not selection_enabled else "in-memory"
    annotated_records = []
    retained_bytes = 0
    spool_handle = None
    spool_path = None
    label_config = load_label_config()
    label_config["max_input_chars"] = label_max_input_chars
    selected_outputs = {"sft": [], "tool_use_sft": [], "router_classification": [], "multi_turn_sft": []}
    episodes = []
    candidate_count = 0
    quality_stats = quality_stats_from_state(init_selection_report_state(), k_threshold)
    user_task_stats = user_task_stats_from_state(init_selection_report_state(), k_threshold)
    try:
        if selection_enabled or not dry_run:
            lock_path = acquire_run_lock(output_root_path, date, run_id)
        if not dry_run:
            output_root_path, tmp_root, backup_root = prepare_tmp_roots(output_root_path, date, run_id=run_id)
            handles = open_stream_writers(tmp_root, date, enabled_jsonl_templates(config))
        for index_record, index_error in iter_index_records(input_root, date):
            if index_error is not None:
                index_record_count += 1
                update_stats_for_reject(stats, index_error)
                if not dry_run:
                    write_reject(handles, date, index_error)
                continue
            if limit is not None and files_attempted >= limit:
                break
            index_record_count += 1
            files_attempted += 1
            raw, error = load_audit_record(input_root, index_record)
            if error:
                update_stats_for_reject(stats, error)
                if not dry_run:
                    write_reject(handles, date, error)
                continue
            files_loaded += 1
            canonical, reject = build_canonical_sample(date, index_record, raw)
            if reject:
                update_stats_for_reject(stats, reject)
                if not dry_run:
                    write_reject(handles, date, reject)
                continue
            apply_optional_model_label(
                canonical,
                label_config,
                enable_route_labeler=enable_route_labeler,
                enable_label_snippets=enable_label_snippets,
                max_chars=label_max_input_chars,
            )
            annotate_task_and_quality(canonical, config)
            apply_optional_quality_label(
                canonical,
                label_config,
                enable_quality_labeler=enable_quality_labeler,
                enable_label_snippets=enable_label_snippets,
                max_chars=label_max_input_chars,
            )
            refresh_selection_use_for(canonical, config)
            update_stats_for_canonical(stats, canonical)
            if not dry_run:
                write_canonical_exports(handles, date, canonical)
            if selection_enabled:
                if should_spool_next(len(annotated_records), retained_bytes, canonical, config):
                    if spool_handle is None:
                        mode_used = "spool"
                        spool_path = spool_path_for(output_root_path, date, run_id)
                        spool_path.parent.mkdir(parents=True, exist_ok=True)
                        spool_handle = spool_path.open("w", encoding="utf-8")
                        for retained in annotated_records:
                            write_jsonl_record(spool_handle, retained)
                        annotated_records = []
                        retained_bytes = 0
                    write_jsonl_record(spool_handle, canonical)
                else:
                    annotated_records.append(canonical)
                    retained_bytes += estimate_record_size(canonical)
        if spool_handle is not None:
            spool_handle.close()
            spool_handle = None
        if selection_enabled:
            if spool_path is not None:
                spooled = process_spooled_selection_records(
                    spool_path,
                    config,
                    date,
                    handles if not dry_run else None,
                )
                selected_outputs = spooled["selected_outputs"]
                quality_stats = spooled["quality_stats"]
                user_task_stats = spooled["user_task_stats"]
                candidate_count = spooled["candidate_count"]
                annotated_records = []
                episodes = []
            else:
                apply_dedupe_annotations_to_records(annotated_records, config)
                episodes = build_episodes(annotated_records, config)
                selected_outputs = build_selected_outputs(annotated_records, episodes, config)
                candidate_count = len(annotated_records)
                quality_stats = build_quality_stats(annotated_records, k_threshold)
                user_task_stats = build_user_task_stats(annotated_records, k_threshold)
        finished_at = datetime.datetime.utcnow().isoformat() + "Z"
        manifest = {
            "date": date,
            "input_root": str(input_root),
            "output_root": str(output_root),
            "index_records": index_record_count,
            "files_attempted": files_attempted,
            "files_loaded": files_loaded,
            "accepted": stats["accepted"],
            "rejected": stats["rejected"],
            "reject_reasons": stats["reject_reasons"],
            "pipeline_version": PIPELINE_VERSION,
            "started_at": started_at,
            "finished_at": finished_at,
            "dry_run": bool(dry_run),
            "selection": {
                "enabled": selection_enabled,
                "mode_used": mode_used,
                "candidate_count": candidate_count,
                "selected_counts": {key: len(value) for key, value in selected_outputs.items()},
            },
        }
        if not dry_run:
            if selection_enabled:
                if spool_path is None:
                    for record in [quality_export_record(item) for item in annotated_records]:
                        write_stream_record(handles, "quality/%s.jsonl" % date, record)
                    for episode in episodes:
                        write_stream_record(handles, "episodes/%s.jsonl" % date, episode)
                for record in selected_outputs.get("sft", []):
                    write_stream_record(handles, "selected/sft/%s.jsonl" % date, record)
                for record in selected_outputs.get("tool_use_sft", []):
                    write_stream_record(handles, "selected/tool_use_sft/%s.jsonl" % date, record)
                for record in selected_outputs.get("router_classification", []):
                    write_stream_record(handles, "selected/router_classification/%s.jsonl" % date, record)
                for record in selected_outputs.get("multi_turn_sft", []):
                    write_stream_record(handles, "selected/multi_turn_sft/%s.jsonl" % date, record)
            close_stream_writers(handles)
            handles = {}
            write_json_file(path_under(tmp_root, "reports/%s.stats.json" % date), stats)
            write_json_file(path_under(tmp_root, "manifests/%s.manifest.json" % date), manifest)
            if selection_enabled:
                write_json_file(path_under(tmp_root, "reports/%s.quality_stats.json" % date), quality_stats)
                write_json_file(path_under(tmp_root, "reports/%s.user_task_stats.json" % date), user_task_stats)
                selection_manifest = build_selection_manifest(date, config, mode_used, run_id, annotated_records, selected_outputs, started_at, finished_at, candidate_count=candidate_count)
                write_json_file(path_under(tmp_root, "reports/%s.selection_manifest.json" % date), selection_manifest)
            commit_started = True
            commit_tmp_outputs(output_root_path, date, enabled_output_relatives(date, config), run_id=run_id)
        if spool_path is not None:
            cleanup_run_tmp(output_root_path, date, run_id)
        return manifest
    except Exception as exc:
        try:
            if spool_handle is not None:
                spool_handle.close()
            if handles:
                close_stream_writers(handles)
        finally:
            if tmp_root is not None and not commit_started:
                cleanup_tmp_root(tmp_root, output_root_path)
            if backup_root is not None and not is_rollback_failed_error(exc):
                cleanup_tmp_root(backup_root, output_root_path)
            if spool_path is not None:
                cleanup_run_tmp(output_root_path, date, run_id)
        raise
    finally:
        release_run_lock(lock_path, output_root_path, run_id=run_id)


def yesterday_date():
    return (datetime.date.today() - datetime.timedelta(days=1)).isoformat()


def date_range(start_date, end_date):
    validate_date_string(start_date)
    validate_date_string(end_date)
    start = datetime.datetime.strptime(start_date, "%Y-%m-%d").date()
    end = datetime.datetime.strptime(end_date, "%Y-%m-%d").date()
    if start > end:
        raise ValueError("start_date must be before or equal to end_date")
    current = start
    dates = []
    while current <= end:
        dates.append(current.isoformat())
        current += datetime.timedelta(days=1)
    return dates


def non_negative_int(value):
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be greater than or equal to 0")
    return parsed


def positive_float(value):
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number")
    if not math.isfinite(parsed) or parsed < 0.0:
        raise argparse.ArgumentTypeError("must be a non-negative finite number")
    return parsed


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Clean audit logs into training-ready datasets."
    )
    parser.add_argument("--input-root", default=DEFAULT_INPUT_ROOT)
    parser.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--date")
    parser.add_argument("--start-date")
    parser.add_argument("--end-date")
    parser.add_argument("--yesterday", action="store_true")
    parser.add_argument("--limit", type=non_negative_int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--disable-selection", action="store_true")
    parser.add_argument("--disable-episodes", action="store_true")
    parser.add_argument("--disable-diagnostics", action="store_true")
    parser.add_argument("--compat-output-set", action="store_true")
    parser.add_argument("--enable-route-labeler", action="store_true")
    parser.add_argument("--enable-quality-labeler", action="store_true")
    parser.add_argument("--enable-label-snippets", action="store_true")
    parser.add_argument("--selected-min-score", type=positive_float, default=0.6)
    parser.add_argument("--router-min-score", type=positive_float, default=0.5)
    parser.add_argument("--sft-min-score", type=positive_float, default=0.6)
    parser.add_argument("--tool-use-min-score", type=positive_float, default=0.6)
    parser.add_argument("--multi-turn-min-score", type=positive_float, default=0.6)
    parser.add_argument("--max-selected-sft-per-user-per-day", type=non_negative_int, default=1000)
    parser.add_argument("--max-selected-router-per-user-per-day", type=non_negative_int, default=2000)
    parser.add_argument("--max-selected-tool-use-per-user-per-day", type=non_negative_int, default=1000)
    parser.add_argument("--max-selected-per-task-fingerprint-per-day", type=non_negative_int, default=200)
    parser.add_argument("--max-high-value-per-task-fingerprint-per-day", type=non_negative_int, default=50)
    parser.add_argument("--label-max-input-chars", type=non_negative_int, default=1200)
    parser.add_argument("--max-in-memory-samples", type=non_negative_int, default=DEFAULT_MAX_IN_MEMORY_SAMPLES)
    parser.add_argument("--max-selection-memory-mb", type=non_negative_int, default=DEFAULT_MAX_SELECTION_MEMORY_MB)
    parser.add_argument("--selection-mode", choices=("auto", "in-memory", "spool"), default="auto")
    parser.add_argument("--k-threshold", type=non_negative_int, default=DEFAULT_K_THRESHOLD)
    args = parser.parse_args(argv)
    if args.compat_output_set and (args.enable_route_labeler or args.enable_quality_labeler or args.enable_label_snippets):
        parser.error("--compat-output-set conflicts with model labeler and snippet flags")
    if args.enable_label_snippets and not (args.enable_route_labeler or args.enable_quality_labeler):
        parser.error("--enable-label-snippets requires a labeler flag")
    return args


def resolve_dates(args):
    has_range = bool(args.start_date or args.end_date)
    selector_count = sum([bool(args.yesterday), bool(args.date), has_range])
    if selector_count != 1:
        raise SystemExit(
            "Provide exactly one of --yesterday, --date, or --start-date with --end-date"
        )
    if args.yesterday:
        return [yesterday_date()]
    if args.date:
        try:
            return [validate_date_string(args.date)]
        except ValueError as exc:
            raise SystemExit(str(exc))
    if not (args.start_date and args.end_date):
        raise SystemExit("Provide --start-date with --end-date")
    try:
        return date_range(args.start_date, args.end_date)
    except ValueError as exc:
        raise SystemExit(str(exc))


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    for date in resolve_dates(args):
        result = process_date(
            args.input_root,
            args.output_root,
            date,
            limit=args.limit,
            dry_run=args.dry_run,
            disable_selection=args.disable_selection,
            disable_episodes=args.disable_episodes,
            disable_diagnostics=args.disable_diagnostics,
            compat_output_set=args.compat_output_set,
            enable_route_labeler=args.enable_route_labeler,
            enable_quality_labeler=args.enable_quality_labeler,
            enable_label_snippets=args.enable_label_snippets,
            selected_min_score=args.selected_min_score,
            router_min_score=args.router_min_score,
            sft_min_score=args.sft_min_score,
            tool_use_min_score=args.tool_use_min_score,
            multi_turn_min_score=args.multi_turn_min_score,
            max_selected_sft_per_user_per_day=args.max_selected_sft_per_user_per_day,
            max_selected_router_per_user_per_day=args.max_selected_router_per_user_per_day,
            max_selected_tool_use_per_user_per_day=args.max_selected_tool_use_per_user_per_day,
            max_selected_per_task_fingerprint_per_day=args.max_selected_per_task_fingerprint_per_day,
            max_high_value_per_task_fingerprint_per_day=args.max_high_value_per_task_fingerprint_per_day,
            label_max_input_chars=args.label_max_input_chars,
            max_in_memory_samples=args.max_in_memory_samples,
            max_selection_memory_mb=args.max_selection_memory_mb,
            selection_mode=args.selection_mode,
            k_threshold=args.k_threshold,
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
