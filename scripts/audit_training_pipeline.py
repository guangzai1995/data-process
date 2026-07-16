#!/usr/bin/env python3
"""Clean audit logs into training-ready datasets."""

PIPELINE_VERSION = "2026.07.16"
DEFAULT_INPUT_ROOT = "/isos_data_share/audit"
DEFAULT_OUTPUT_ROOT = "audit_training"


import hashlib
import re


REDACTION_PATTERNS = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone", re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")),
    ("cn_id", re.compile(r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)")),
    ("bank_card", re.compile(r"(?<!\d)\d(?:[ -]?\d){15,18}(?!\d)")),
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
