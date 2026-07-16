#!/usr/bin/env python3
"""Clean audit logs into training-ready datasets."""

PIPELINE_VERSION = "2026.07.16"
DEFAULT_INPUT_ROOT = "/isos_data_share/audit"
DEFAULT_OUTPUT_ROOT = "audit_training"


import argparse
import datetime
import hashlib
import json
import math
import os
import pathlib
import re
import shutil
import sys
import urllib.request


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
                    parse_int=parse_limited_int,
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


USAGE_TOKEN_FIELDS = ("prompt_tokens", "completion_tokens", "total_tokens")
MAX_USAGE_TOKENS = 10 ** 9


def parse_finite_float(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def parse_limited_int(value):
    parsed = int(value)
    if parsed > MAX_USAGE_TOKENS:
        raise ValueError("integer JSON number too large")
    return parsed


def sanitize_usage(usage):
    if not isinstance(usage, dict):
        return None
    sanitized = {}
    for key in USAGE_TOKEN_FIELDS:
        if key not in usage:
            continue
        value = usage[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            return None
        if isinstance(value, float):
            if not value.is_integer():
                return None
            value = int(value)
        if value > MAX_USAGE_TOKENS:
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
            "file_path_hash": file_path_hash(index_record),
            "tenant_hash": hash_identifier(raw_record.get("tenant_id")),
            "user_hash": hash_identifier(raw_record.get("user_id")),
            "session_hash": hash_identifier(raw_record.get("session_id")),
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


def call_label_model(router_record, config, urlopen=None):
    if not config.get("enabled"):
        return None, "labeler_disabled"
    prompt = {
        "task": "classify_route",
        "labels": sorted(ROUTE_LABELS),
        "sample": router_record,
        "response_format": {
            "label": "string",
            "confidence": "number",
            "reason": "string",
        },
    }
    body = json.dumps(
        {
            "model": config["model"],
            "messages": [
                {
                    "role": "system",
                    "content": "Return only JSON for route classification.",
                },
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
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
    parsed = parse_label_response(content)
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
            label_queue.append({
                "sample_id": canonical["sample_id"],
                "reason": "low_confidence_route",
                "router": router_record,
            })
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


def output_relative_paths(date):
    validate_date_string(date)
    paths = [template % date for template in JSONL_OUTPUTS]
    paths.append("reports/%s.stats.json" % date)
    paths.append("manifests/%s.manifest.json" % date)
    return paths


def prepare_tmp_roots(output_root, date):
    validate_date_string(date)
    output_root = pathlib.Path(output_root)
    tmp_root = lexical_path_under(output_root, ".tmp/%s" % date)
    backup_root = lexical_path_under(output_root, ".tmp/%s.backup" % date)
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


def commit_tmp_outputs(output_root, date, relative_paths):
    output_root = pathlib.Path(output_root)
    tmp_root = lexical_path_under(output_root, ".tmp/%s" % date)
    backup_root = lexical_path_under(output_root, ".tmp/%s.backup" % date)
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


def open_stream_writers(tmp_root, date):
    handles = {}
    try:
        for relative in [template % date for template in JSONL_OUTPUTS]:
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
    if record is not None:
        write_jsonl_record(handles[relative], record)


def apply_optional_model_label(canonical, label_config):
    if not label_config.get("enabled"):
        return
    router_record = export_router(canonical)
    model_label, _error = call_label_model(router_record, label_config)
    normalized = normalize_model_label(model_label)
    if normalized is not None:
        canonical["routing"]["model_label"] = normalized


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
            {
                "sample_id": canonical["sample_id"],
                "reason": "low_confidence_route",
                "router": router_record,
            },
        )


def write_reject(handles, date, reject):
    write_stream_record(handles, "reports/%s.rejects.jsonl" % date, reject)


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
                parse_int=parse_limited_int,
            ), None
    except ValueError:
        return None, {
            "request_id": index_record.get("request_id"),
            "file_path_hash": file_path_hash(index_record),
            "reason": "bad_detail_json",
        }


def process_date(input_root, output_root, date, limit=None, dry_run=False):
    validate_date_string(date)
    started_at = datetime.datetime.utcnow().isoformat() + "Z"
    output_root_path = pathlib.Path(output_root)
    tmp_root = None
    backup_root = None
    handles = {}
    stats = init_stats()
    index_record_count = 0
    files_attempted = 0
    files_loaded = 0
    commit_started = False
    label_config = load_label_config()
    try:
        if not dry_run:
            output_root_path, tmp_root, backup_root = prepare_tmp_roots(output_root_path, date)
            handles = open_stream_writers(tmp_root, date)
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
            apply_optional_model_label(canonical, label_config)
            update_stats_for_canonical(stats, canonical)
            if not dry_run:
                write_canonical_exports(handles, date, canonical)
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
        }
        if not dry_run:
            close_stream_writers(handles)
            handles = {}
            write_json_file(path_under(tmp_root, "reports/%s.stats.json" % date), stats)
            write_json_file(path_under(tmp_root, "manifests/%s.manifest.json" % date), manifest)
            commit_started = True
            commit_tmp_outputs(output_root_path, date, output_relative_paths(date))
        return manifest
    except Exception as exc:
        try:
            if handles:
                close_stream_writers(handles)
        finally:
            if tmp_root is not None and not commit_started:
                cleanup_tmp_root(tmp_root, output_root_path)
            if backup_root is not None and not is_rollback_failed_error(exc):
                cleanup_tmp_root(backup_root, output_root_path)
        raise


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
    return parser.parse_args(argv)


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
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
