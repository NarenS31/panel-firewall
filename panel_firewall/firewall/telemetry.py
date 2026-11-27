"""Opt-in, anonymized exploit telemetry: the data layer for a shared threat graph.

Off unless the policy says `telemetry: true`. After a BLOCK or a HOLD (needs consent) the engine calls `record_verdict`, which
distils the event into an `ExploitSignature` and stores it in the `exploit_signatures` table of the ledger database. A signature
holds ONLY these fields:

  pattern_type      cap_split | velocity_burst | false_completion | forbidden_tool | sql_injection | circuit_breaker_trip
  tool_category     payment | database | filesystem | communication | other   (from tool-name keywords; the name itself is never kept)
  rule_triggered    the policy rule type that fired (rate_limit, max_amount, block_if, protected, ...)
  amount_ratio      attempted amount / the policy cap (2.0 = tried twice the limit); never the amount
  window_position   e.g. "5th of 5 allowed": executions already in the rate window
  session_spread    how many different conversations this entity (or tool) appeared in within the window; a count, never the ids
  timestamp_bucket  unix time rounded to the nearest hour
  verdict           block | needs_consent

It never stores tool names, arguments, customer data, conversation ids, keys, amounts or reason text. `build_signature` takes the
raw facts and returns only the fields above, so there is no path for anything else to leak into the table or the upload.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import asdict, dataclass

from panel_firewall.firewall.summary import rule_of

log = logging.getLogger("panel_firewall.firewall")

PATTERN_TYPES = ("cap_split", "velocity_burst", "false_completion", "forbidden_tool", "sql_injection", "circuit_breaker_trip")
CATEGORIES = ("payment", "database", "filesystem", "communication", "other")
UPLOAD_EVERY = 300.0            # seconds between cloud batches
DEFAULT_WINDOW = 86400.0        # session_spread window when no rate rule defines one

# rule type (summary.rule_of) -> pattern. Anything unlisted is a plain policy violation: forbidden_tool.
_PATTERN = {"max_amount": "cap_split", "max_total_amount": "cap_split", "max_total_outflow": "cap_split", "consent_over_amount": "cap_split",
            "rate_limit": "velocity_burst", "entity_velocity": "velocity_burst", "duplicate_guard": "velocity_burst",
            "sql_guard": "sql_injection", "circuit_breaker": "circuit_breaker_trip"}
_CATEGORY_WORDS = (
    ("payment", ("refund", "pay", "credit", "charge", "withdraw", "transfer", "payout", "invoice", "balance", "billing", "stripe", "checkout", "discount", "coupon")),
    ("database", ("sql", "query", "db", "database", "table", "row", "record", "insert", "select")),
    ("filesystem", ("file", "path", "fs", "dir", "folder", "disk", "directory")),
    ("communication", ("email", "mail", "sms", "message", "slack", "notify", "send", "chat", "call", "tweet", "post")),
)
_FAMILY_CATEGORY = {"refund": "payment", "credit": "payment", "charge": "payment", "transfer": "payment", "discount": "payment",
                    "send": "communication", "delete": "database", "update": "database", "insert": "database", "cancel": "payment"}


def tool_category(tool: str) -> str:
    """Generic category from tool-name keywords. The name itself is discarded."""
    t = str(tool or "").lower()
    for cat, words in _CATEGORY_WORDS:
        if any(w in t for w in words):
            return cat
    return "other"


def hour_bucket(ts: float) -> int:
    return int(round(ts / 3600.0)) * 3600


def _ordinal(n: int) -> str:
    return f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


@dataclass
class ExploitSignature:
    pattern_type: str
    tool_category: str
    rule_triggered: str
    amount_ratio: float | None
    window_position: str | None
    session_spread: int
    timestamp_bucket: int
    verdict: str                  # block | needs_consent

    def to_dict(self) -> dict:
        return asdict(self)


def pattern_for(rule: str) -> str:
    return _PATTERN.get(rule, "forbidden_tool")


def build_signature(*, rule: str, tool: str, verdict: str, ts: float, ratio: float | None = None, position: str | None = None,
                    spread: int = 1, pattern: str | None = None, category: str | None = None) -> ExploitSignature:
    pat = pattern or pattern_for(rule)
    assert pat in PATTERN_TYPES, pat
    return ExploitSignature(pat, category or tool_category(tool), rule, None if ratio is None else round(float(ratio), 2),
                            position, max(int(spread), 1), hour_bucket(ts), verdict)


# ---------------------------------------------------------------------------------------------------- the local log
class ExploitLog:
    """The `exploit_signatures` table, inside the ledger database (it is NOT an append-only `events` row: `uploaded_at` is bookkeeping)."""
    SCHEMA = """CREATE TABLE IF NOT EXISTS exploit_signatures (
      id INTEGER PRIMARY KEY AUTOINCREMENT, pattern_type TEXT NOT NULL, tool_category TEXT NOT NULL, rule_triggered TEXT NOT NULL,
      amount_ratio REAL, window_position TEXT, session_spread INTEGER NOT NULL, timestamp_bucket INTEGER NOT NULL,
      verdict TEXT NOT NULL, uploaded_at REAL)"""

    def __init__(self, ledger):
        self.ledger = ledger
        with ledger._lock:
            ledger._db.execute(self.SCHEMA)

    def add(self, s: ExploitSignature) -> int:
        with self.ledger._lock:
            cur = self.ledger._db.execute(
                "INSERT INTO exploit_signatures(pattern_type, tool_category, rule_triggered, amount_ratio, window_position, session_spread, "
                "timestamp_bucket, verdict) VALUES (?,?,?,?,?,?,?,?)",
                (s.pattern_type, s.tool_category, s.rule_triggered, s.amount_ratio, s.window_position, s.session_spread, s.timestamp_bucket, s.verdict))
            return cur.lastrowid

    _COLS = "pattern_type, tool_category, rule_triggered, amount_ratio, window_position, session_spread, timestamp_bucket, verdict"

    def _sigs(self, rows) -> list[ExploitSignature]:
        return [ExploitSignature(*r) for r in rows]

    def since(self, since_ts: float = 0.0) -> list[ExploitSignature]:
        """Signatures from `since_ts` on. Buckets are rounded to the nearest hour, so this is accurate to within 30 minutes."""
        return self._sigs(self.ledger._rows(f"SELECT {self._COLS} FROM exploit_signatures WHERE timestamp_bucket >= ? ORDER BY id",
                                            (since_ts - 1800,)))

    def unuploaded(self, limit: int = 200) -> list[tuple[int, ExploitSignature]]:
        rows = self.ledger._rows(f"SELECT id, {self._COLS} FROM exploit_signatures WHERE uploaded_at IS NULL ORDER BY id LIMIT ?", (limit,))
        return [(r[0], ExploitSignature(*r[1:])) for r in rows]

    def mark_uploaded(self, ids: list[int], when: float | None = None) -> None:
        with self.ledger._lock:
            self.ledger._db.executemany("UPDATE exploit_signatures SET uploaded_at=? WHERE id=?", [(when or time.time(), i) for i in ids])


def summarize(sigs: list[ExploitSignature]) -> dict:
    """Counts by pattern / category / rule / verdict, plus the biggest cap overshoot and the widest session spread."""
    def count(attr):
        out: dict = {}
        for s in sigs:
            out[getattr(s, attr)] = out.get(getattr(s, attr), 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))
    ratios = [s.amount_ratio for s in sigs if s.amount_ratio is not None]
    return {"total": len(sigs), "by_pattern": count("pattern_type"), "by_category": count("tool_category"), "by_rule": count("rule_triggered"),
            "by_verdict": count("verdict"), "max_amount_ratio": max(ratios) if ratios else None,
            "max_session_spread": max((s.session_spread for s in sigs), default=0)}


def format_summary(sm: dict, since: str = "") -> str:
    if not sm["total"]:
        return f"No exploit patterns recorded{' in the last ' + since if since else ''}. (Telemetry is off unless the policy has `telemetry: true`.)"
    lines = [f"{sm['total']} exploit pattern(s){' in the last ' + since if since else ''} (anonymized; stored locally)"]
    for title, k in (("pattern", "by_pattern"), ("tool category", "by_category"), ("rule", "by_rule"), ("verdict", "by_verdict")):
        lines.append(f"  by {title}: " + ", ".join(f"{n} x {c}" for n, c in sm[k].items()))
    if sm["max_amount_ratio"] is not None:
        lines.append(f"  largest attempt vs cap: {sm['max_amount_ratio']:g}x the limit")
    lines.append(f"  widest session spread: {sm['max_session_spread']} conversation(s)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------- engine hooks
def enabled(policy) -> bool:
    return policy is not None and policy.raw.get("telemetry") is True


def _cap_for(rule: str, tool_rule: dict, policy) -> float | None:
    mo = policy.raw.get("max_total_outflow") or {}
    cap = {"max_total_amount": (tool_rule.get("max_total_amount") or {}).get("amount"), "max_total_outflow": mo.get("amount"),
           "consent_over_amount": tool_rule.get("consent_over_amount"), "max_amount": tool_rule.get("max_amount")}.get(rule)
    if cap is None:
        cap = tool_rule.get("max_amount", tool_rule.get("consent_over_amount"))
    return float(cap) if isinstance(cap, (int, float)) and not isinstance(cap, bool) and cap > 0 else None


def _spread_and_position(ledger, policy, tool: str, tool_rule: dict, args: dict, conv: str, now: float, rule: str):
    """(session_spread, window_position) from the ledger: how many conversations the entity (or the tool) appeared in, and how full the window is."""
    ev, rl = tool_rule.get("entity_velocity"), tool_rule.get("rate_limit")
    window = float((ev or {}).get("per_seconds") or (rl or {}).get("per_seconds") or DEFAULT_WINDOW)
    since = now - window
    q = "SELECT DISTINCT conversation_id FROM events WHERE event='executed' AND tool=? AND ts>?"
    a: list = [tool, since]
    if ev and args.get(ev["field"]) not in (None, "") and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", ev["field"]):
        v = args[ev["field"]]
        q = ("SELECT DISTINCT e.conversation_id FROM events e JOIN events r ON r.idem_key=e.idem_key AND r.event='requested' "
             "WHERE e.event='executed' AND e.tool=? AND e.ts>? AND json_extract(r.data, ?) = ?")
        a += [f'$.args."{ev["field"]}"', v if isinstance(v, (int, float, str)) and not isinstance(v, bool) else str(v)]
    convs = {r[0] for r in ledger._rows(q, a)}
    convs.add(conv)
    pos = None
    if rule == "entity_velocity" and ev:
        n = len(ledger.executed_with_field(tool, ev["field"], args.get(ev["field"]), since))
        pos = f"{_ordinal(n)} of {ev['max_actions']:g} allowed"
    elif rl:
        n = len(ledger.executed_for(tool, now - float(rl["per_seconds"])))
        pos = f"{_ordinal(n)} of {rl['max']:g} allowed"
    return len(convs), pos


def record_verdict(policy, ledger, action, reasons: list[str], verdict: str, now: float | None = None) -> ExploitSignature | None:
    """Called by the engine after a block or hold. No-op unless the policy opted in. Never raises: telemetry must not change a verdict."""
    try:
        if not enabled(policy) or not reasons:
            return None
        now = time.time() if now is None else now
        rule = rule_of(reasons[0])
        tool_rule = policy.rule_for(action.tool) or {}
        args = action.args if isinstance(action.args, dict) else {}
        amt = args.get(tool_rule.get("amount_field", "amount"))
        cap = _cap_for(rule, tool_rule, policy)
        ratio = float(amt) / cap if isinstance(amt, (int, float)) and not isinstance(amt, bool) and cap and amt >= 0 and amt == amt else None
        spread, pos = _spread_and_position(ledger, policy, action.tool, tool_rule, args, action.conversation_id, now, rule)
        sig = build_signature(rule=rule, tool=action.tool, verdict=verdict, ts=now, ratio=ratio, position=pos, spread=spread)
        ExploitLog(ledger).add(sig)
        try:
            from panel_firewall.firewall import learn
            learn.record_exploit(ledger, policy, action, rule, sig, now)
        except Exception:
            log.debug("telemetry: could not record a learned pattern", exc_info=True)
        return sig
    except Exception:
        log.debug("telemetry: could not record a signature", exc_info=True)
        return None


def record_breaker_trip(policy, ledger, now: float | None = None) -> ExploitSignature | None:
    try:
        if not enabled(policy):
            return None
        sig = build_signature(rule="circuit_breaker", tool="", verdict="block", ts=time.time() if now is None else now, category="other")
        ExploitLog(ledger).add(sig)
        return sig
    except Exception:
        log.debug("telemetry: could not record a breaker trip", exc_info=True)
        return None


def record_false_completion(policy, ledger, conversation_id: str, claims: list, now: float | None = None) -> ExploitSignature | None:
    """A reply claimed an action that the ledger does not back. Only the claim's family (refund, delete, ...) -> category is kept."""
    try:
        if not enabled(policy):
            return None
        fams = [c.family for c in claims if not c.backed and c.family]
        cat = _FAMILY_CATEGORY.get(fams[0], "other") if fams else "other"
        sig = build_signature(rule="claim_check", tool="", verdict="block", ts=time.time() if now is None else now, pattern="false_completion",
                              category=cat, spread=1)
        ExploitLog(ledger).add(sig)
        return sig
    except Exception:
        log.debug("telemetry: could not record a false completion", exc_info=True)
        return None
