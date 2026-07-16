#!/usr/bin/env python3
"""Clean audit logs into training-ready datasets."""

PIPELINE_VERSION = "2026.07.16"
DEFAULT_INPUT_ROOT = "/isos_data_share/audit"
DEFAULT_OUTPUT_ROOT = "audit_training"


import hashlib
import json
import pathlib
import re


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
                record = json.loads(stripped)
            except ValueError:
                yield None, {"line": line_number, "reason": "bad_index_json"}
                continue
            if (
                not isinstance(record, dict)
                or not record.get("request_id")
                or not record.get("file_path")
            ):
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


def reject_record(date, index_record, reason):
    return {
        "date": date,
        "request_id": index_record.get("request_id"),
        "file_path": index_record.get("file_path"),
        "reason": reason,
    }


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
    choice = first_response_choice(raw_record)
    if choice is None:
        return None, reject_record(date, index_record, "missing_choices")
    response_message = response_message_from_choice(choice)
    response_text = assistant_text_from_choice(choice)
    if not response_text and not response_message.get("tool_calls"):
        return None, reject_record(date, index_record, "empty_assistant_response")
    if len(stable_json(messages)) > max_prompt_chars:
        return None, reject_record(date, index_record, "prompt_too_long")
    if len(stable_json(response_message)) > max_response_chars:
        return None, reject_record(date, index_record, "response_too_long")

    redacted_messages, message_stats = redact_value_tree(messages)
    redacted_tools, tool_stats = redact_value_tree(request_body.get("tools") or [])
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
            "tool_choice": redacted_params.get("tool_choice"),
            "params": redacted_params,
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
        if message.get("role") == "user":
            return extract_text_content(message.get("content"))
    return ""


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


def final_route_label(canonical):
    model_label = canonical["routing"].get("model_label")
    if isinstance(model_label, dict):
        label = model_label.get("label")
        confidence = model_label.get("confidence")
        if (
            isinstance(label, str)
            and label in ROUTE_LABELS
            and isinstance(confidence, (int, float))
            and not isinstance(confidence, bool)
            and confidence >= 0.75
        ):
            return label, "high"
    rule_label = classify_by_rules(canonical)
    if rule_label in ROUTE_LABELS:
        return rule_label, "medium"
    return "unknown", "low"


def export_sft(canonical):
    message = canonical["response"]["message"]
    content = extract_text_content(message.get("content"))
    if (
        not content
        or has_tool_interaction(canonical)
        or canonical["response"].get("finish_reason") == "length"
    ):
        return None
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
            "model_label": canonical["routing"].get("model_label"),
            "final_label": final_label,
            "confidence": confidence,
        },
    }
