"""PII scrubbing for anything that leaves the ledger as a summary, report or export.

Masks: email addresses, phone numbers, card-like numbers (13-19 digits, spaced/dashed or not), and API-key-like strings (known
vendor prefixes, JWTs, `Bearer` tokens, AWS access key ids, long mixed-case/digit tokens). Replacement tokens are
`[email]`, `[phone]`, `[card]`, `[secret]`.

Deliberately NOT masked: SHA-256/SHA-1/MD5-length lowercase hex strings (receipt and action hashes are the point of the export).
This is pattern matching, not a guarantee: names, street addresses and free text with no recognisable shape pass through. That is
why raw arguments are never exported unless `--include-raw-args` is given.
"""
from __future__ import annotations

import re

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_KEY_PREFIXED = re.compile(
    r"\b(?:sk|pk|rk|whsec)_(?:live|test)_[A-Za-z0-9]{8,}|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}"
    r"|\bxox[abprs]-[A-Za-z0-9\-]{10,}|\bAKIA[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_\-]{30,}|\bsk-[A-Za-z0-9_\-]{20,}"
    r"|\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
_BEARER = re.compile(r"(?i)\b(bearer|token|api[_-]?key|secret|password|passwd)(\s*[:=]\s*|\s+)(['\"]?)[^\s'\",;]{6,}")
_CARD = re.compile(r"(?<![\w.])(?:\d[ \-]?){12,18}\d(?![\w])")
_PHONE = re.compile(r"(?<![\w.])(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)[\s.\-]?|\d{2,4}[\s.\-])\d{3,4}[\s.\-]?\d{3,4}(?![\w])")
_LONG = re.compile(r"(?<![A-Za-z0-9_\-/.])[A-Za-z0-9_\-]{24,}(?![A-Za-z0-9_\-])")
_HASHY = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$")


def _long(m: re.Match) -> str:
    t = m.group(0)
    if _HASHY.match(t):
        return t
    if re.search(r"[A-Za-z]", t) and re.search(r"\d", t):
        return "[secret]"
    return t


def scrub_text(s: str) -> str:
    if not isinstance(s, str) or not s:
        return s
    s = _EMAIL.sub("[email]", s)
    s = _KEY_PREFIXED.sub("[secret]", s)
    s = _BEARER.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}[secret]", s)
    s = _CARD.sub(lambda m: "[card]" if 13 <= len(re.sub(r"\D", "", m.group(0))) <= 19 else m.group(0), s)
    s = _PHONE.sub("[phone]", s)
    s = _LONG.sub(_long, s)
    return s


def scrub(obj):
    """Recursively scrub every string (dict keys are kept; they are field names, not user data)."""
    if isinstance(obj, str):
        return scrub_text(obj)
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(scrub(x) for x in obj)
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()}
    return obj
