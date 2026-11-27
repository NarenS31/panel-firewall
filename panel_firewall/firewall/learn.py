"""Learned patterns: observe -> extract pattern -> (human marks it) -> suggest a rule. Nothing here changes a verdict.

The `learned_patterns` table records recurring things Panel flagged, from three sources:
  local anomaly   `anomaly.check` flagged an action (amount_outlier, frequency_spike, value_novelty, field_anomaly, length_outlier,
                  sequence_anomaly, timing_anomaly)
  local exploit   with `telemetry: true`, a block/hold that telemetry.py turned into a signature (cap_split, velocity_burst, ...)
  cloud           the threat feed (`GET /v1/telemetry/threat-feed`) pushed a pattern seen in other deployments
Every row starts `unconfirmed`. A human marks it with `usepanel learn`:
  threat          real. It becomes a rule suggestion (`usepanel suggest`); the human still has to accept and deploy that rule.
  false_positive  the flag was wrong. For a local anomaly pattern the matching anomaly threshold for that tool is raised
                  (`anomaly_tuning`), so it is not re-flagged. Policy rules are never loosened automatically.
Local rows keep the tool name and field (this database never leaves the machine); cloud rows only ever carry a category.
Only the anonymized `exploit_signatures` rows are uploaded (telemetry.py); this table is never uploaded.
"""
from __future__ import annotations

import logging
import re
import time

from panel_firewall.firewall.types import sha256_hex

log = logging.getLogger("panel_firewall.firewall")

ANOMALY_PATTERN = {"amount": "amount_outlier", "frequency": "frequency_spike", "value": "value_novelty", "field": "field_anomaly",
                   "length": "length_outlier", "sequence": "sequence_anomaly", "timing": "timing_anomaly"}
PATTERN_KIND = {v: k for k, v in ANOMALY_PATTERN.items()}
EXPLOIT_TYPES = ("cap_split", "velocity_burst", "false_completion", "forbidden_tool", "sql_injection", "circuit_breaker_trip")
ALL_TYPES = EXPLOIT_TYPES + tuple(ANOMALY_PATTERN.values())
CATEGORIES = ("payment", "database", "filesystem", "communication", "other")
STATUSES = ("unconfirmed", "threat", "false_positive")
SOURCES = ("local", "cloud")
SCHEMA = """CREATE TABLE IF NOT EXISTS learned_patterns (
  id INTEGER PRIMARY KEY AUTOINCREMENT, sig TEXT NOT NULL UNIQUE, pattern_type TEXT NOT NULL, source TEXT NOT NULL,
  tool TEXT, category TEXT NOT NULL, rule TEXT NOT NULL, field TEXT, threshold REAL, count INTEGER NOT NULL,
  deployments INTEGER, status TEXT NOT NULL DEFAULT 'unconfirmed', first_seen REAL NOT NULL, last_seen REAL NOT NULL,
  decided_by TEXT, decided_at REAL)"""
COLS = "id, pattern_type, source, tool, category, rule, field, threshold, count, deployments, status, first_seen, last_seen, decided_by, decided_at"
_KEYS = COLS.split(", ")


def _init(ledger) -> None:
    with ledger._lock:
        ledger._db.execute(SCHEMA)


def _row(r) -> dict:
    return dict(zip(_KEYS, r))


def _sig(source, pattern_type, tool, category, rule, field, threshold) -> str:
    return sha256_hex("|".join(str(x) for x in (source, pattern_type, tool, category, rule, field, threshold)))[:20]


def _upsert(ledger, *, source, pattern_type, tool, category, rule, field=None, threshold=None, count=1, deployments=None, absolute=False,
            now: float | None = None) -> int:
    """Insert, or bump the count (local: +count; cloud: the feed's own absolute total)."""
    _init(ledger)
    now = time.time() if now is None else now
    sig = _sig(source, pattern_type, tool, category, rule, field, threshold)
    with ledger._lock:
        ledger._db.execute(
            "INSERT INTO learned_patterns(sig, pattern_type, source, tool, category, rule, field, threshold, count, deployments, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(sig) DO UPDATE SET "
            f"count = {'MAX(count, excluded.count)' if absolute else 'count + excluded.count'}, last_seen = excluded.last_seen, "
            "deployments = COALESCE(excluded.deployments, deployments)",
            (sig, pattern_type, source, tool, category, rule, field, threshold, count, deployments, now, now))
        return ledger._db.execute("SELECT id FROM learned_patterns WHERE sig=?", (sig,)).fetchone()[0]


# ----------------------------------------------------------------------------------------------------- recording
def record_anomaly(ledger, tool: str, anomaly, now: float | None = None) -> int:
    from panel_firewall.firewall.telemetry import tool_category
    return _upsert(ledger, source="local", pattern_type=ANOMALY_PATTERN[anomaly.kind], tool=tool, category=tool_category(tool),
                   rule="anomaly:" + anomaly.kind, field=anomaly.field, now=now)


def record_exploit(ledger, policy, action, rule: str, sig, now: float | None = None) -> int:
    """From telemetry.record_verdict: keep the tool, the field and the threshold that fired (locally only)."""
    tr = policy.rule_for(action.tool) or {}
    field, threshold = None, None
    if rule == "entity_velocity" and tr.get("entity_velocity"):
        field, threshold = tr["entity_velocity"]["field"], float(tr["entity_velocity"]["max_actions"])
    elif rule == "rate_limit" and tr.get("rate_limit"):
        threshold = float(tr["rate_limit"]["max"])
    elif rule == "duplicate_guard" and tr.get("duplicate_guard"):
        field = tr["duplicate_guard"]["field"]
    elif rule in ("max_amount", "consent_over_amount", "max_total_amount"):
        field = tr.get("amount_field", "amount")
        v = tr.get("max_amount") if rule == "max_amount" else tr.get("consent_over_amount") if rule == "consent_over_amount" else (tr.get("max_total_amount") or {}).get("amount")
        threshold = float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None
    return _upsert(ledger, source="local", pattern_type=sig.pattern_type, tool=action.tool, category=sig.tool_category, rule=rule, field=field,
                   threshold=threshold, now=now)


# ----------------------------------------------------------------------------------------------------- cloud feed
def _num(v, lo, hi):
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and lo <= v <= hi else None


def merge_feed(ledger, payload, now: float | None = None) -> int:
    """Merge a threat-feed response into learned_patterns with source='cloud'. The feed is untrusted input: every field is checked against a
    closed vocabulary or a bounded number, anything else is dropped. Returns how many patterns were accepted. Never enforces anything."""
    items = payload.get("patterns") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return 0
    n = 0
    for it in items[:500]:
        if not isinstance(it, dict):
            continue
        pt, cat, rule = it.get("pattern_type"), it.get("tool_category"), it.get("rule_triggered")
        seen, dep = _num(it.get("seen"), 1, 1e9), _num(it.get("deployments", 1), 1, 1e9)
        if pt not in ALL_TYPES or cat not in CATEGORIES or not isinstance(rule, str) or not re.fullmatch(r"[a-z_:]{1,40}", rule) or seen is None or dep is None:
            continue
        thr = _num(it.get("amount_ratio"), 0, 1e6)
        _upsert(ledger, source="cloud", pattern_type=pt, tool=None, category=cat, rule=rule, threshold=thr, count=int(seen), deployments=int(dep),
                absolute=True, now=now)
        n += 1
    return n


# ----------------------------------------------------------------------------------------------------- review
def patterns(ledger, status: str | None = None, source: str | None = None) -> list[dict]:
    _init(ledger)
    q, a = f"SELECT {COLS} FROM learned_patterns WHERE 1=1", []
    if status:
        q, a = q + " AND status=?", a + [status]
    if source:
        q, a = q + " AND source=?", a + [source]
    return [_row(r) for r in ledger._rows(q + " ORDER BY count DESC, id", a)]


def hints(ledger, tool: str | None) -> dict:
    """How earlier holds of this tool were decided by people: a hint for the reviewer, never an automatic decision."""
    if not tool:
        return {"approved": 0, "denied": 0}
    r = {e: ledger._rows("SELECT COUNT(*) FROM events WHERE tool=? AND event=?", (tool, e))[0][0] for e in ("approved", "denied")}
    return r


def mark(ledger, pattern_id: int, verdict: str, who: str, now: float | None = None) -> str:
    """Record the human's decision. Returns a one-line description of what changed."""
    from panel_firewall.firewall.anomaly import Baselines
    if verdict not in ("threat", "false_positive"):
        raise ValueError("verdict must be 'threat' or 'false_positive'")
    who = (who or "").strip()
    if not who:
        raise ValueError("who is required")
    _init(ledger)
    rows = ledger._rows(f"SELECT {COLS} FROM learned_patterns WHERE id=?", (pattern_id,))
    if not rows:
        raise ValueError(f"no learned pattern {pattern_id}")
    p = _row(rows[0])
    with ledger._lock:
        ledger._db.execute("UPDATE learned_patterns SET status=?, decided_by=?, decided_at=? WHERE id=?",
                           (verdict, who, time.time() if now is None else now, pattern_id))
    if verdict == "threat":
        return f"pattern {pattern_id} marked a real threat; it will be suggested as a rule by `usepanel suggest` (never enforced automatically)"
    kind = PATTERN_KIND.get(p["pattern_type"])
    if p["source"] == "local" and kind and p["tool"]:
        nb = Baselines(ledger).add_bonus(p["tool"], kind)
        return f"pattern {pattern_id} marked a false positive; the '{kind}' anomaly threshold for {p['tool']} is now looser (bonus {nb:g})"
    return f"pattern {pattern_id} marked a false positive; it will not be suggested. Policy rules are never loosened automatically"


def describe(p: dict) -> str:
    where = p["tool"] or f"any {p['category']} tool"
    bits = [f"{p['pattern_type']} on {where}", f"rule {p['rule']}"]
    if p["field"]:
        bits.append(f"field {p['field']}")
    if p["threshold"] is not None:
        bits.append(f"threshold {p['threshold']:g}")
    tail = f"seen {p['count']}x" + (f" in {p['deployments']} deployment(s)" if p["deployments"] else "")
    return f"[{p['id']}] ({p['source']}) " + ", ".join(bits) + f" - {tail}"
