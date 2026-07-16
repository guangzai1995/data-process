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
