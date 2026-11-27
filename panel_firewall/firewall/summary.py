"""Plain-English summaries of ledger events, the shadow-mode report, and scrubbed log exports.

Everything here reads only the ledger and returns data minimised for sharing: tool, verdict, rule, amount, a one-line summary
(scrubbed), receipt hashes. Raw arguments appear only when `include_raw_args=True`.
"""
from __future__ import annotations

import re
import time

from panel_firewall.firewall.scrub import scrub_text

# reason text (as produced by policy.evaluate, sqlguard and the connectors) -> the rule that produced it
_RULES = [
    (r"^anomaly: ", "anomaly"),
    (r"already had a .* ago|which the duplicate guard needs", "duplicate_guard"),
    (r"^circuit breaker", "circuit_breaker"),
    (r"is not allowed by policy", "allowed"),
    (r"^unknown action|no connector handles it", "unknown_action"),
    (r"^missing required field", "required_fields"),
    (r"^missing amount field|must be a finite non-negative number", "amount_field"),
    (r"exceeds the maximum \d", "max_amount"),
    (r"a human must approve", "consent_over_amount"),
    (r"would affect \d+ rows; the maximum|row count could not", "max_rows"),
    (r"would affect \d+ rows; over", "consent_over_rows"),
    (r"matches protected resource", "protected"),
    (r"^blocked: |cannot evaluate condition on .*\(wrong type\)", "block_if"),
    (r"^needs approval: |asking a human", "consent_if"),
    (r"^rate limit", "rate_limit"),
    (r"^cumulative ", "max_total_amount"),
    (r"^entity velocity", "entity_velocity"),
    (r"^total outflow", "max_total_outflow"),
    (r"^approval mode", "approval_mode"),
    (r"outside the allowed folders|absolute path string", "allowed_roots"),
    (r"matches protected pattern", "protected"),
    (r"statements are not allowed|WITHOUT a WHERE|without a WHERE|always-true WHERE|table '.*' is protected|internal table|nested|CTE|"
     r"could not be parsed|could not analyse|statement target|row counter|affected rows|no database is configured", "sql_guard"),
    (r"must be a|must look like", "argument_check"),
    (r"not found", "lookup"),
]
_RULES = [(re.compile(p), r) for p, r in _RULES]


def rule_of(reason: str) -> str:
    for rx, name in _RULES:
        if rx.search(reason):
            return name
    return "other"


def parse_since(s: str, now: float | None = None) -> float:
    """'48h', '30m', '7d', '90s' -> a unix timestamp that long ago."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhd])\s*", s or "")
    if not m:
        raise ValueError("--since looks like 48h, 30m, 7d")
    return (now if now is not None else time.time()) - float(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def _money(v) -> str:
    return f"${v:,.2f}".replace(".00", "") if isinstance(v, (int, float)) else ""


def summarize(tool: str, event: str, data: dict) -> str:
    """One scrubbed line a non-engineer can read."""
    amt = data.get("amount")
    of = f" of {_money(amt)}" if amt else ""
    why = "; ".join(data.get("reasons") or [])
    if event == "shadow":
        verb = {"block": "would have been BLOCKED", "ask": "would have needed a human's approval"}.get(data.get("would"), "was flagged")
        return scrub_text(f"{tool}{of} {verb}: {why}" if why else f"{tool}{of} {verb}")
    verb = {"executed": "ran", "read": "ran (read)", "blocked": "was blocked", "pending": "is waiting for approval",
            "approved": "was approved by a human", "denied": "was denied by a human", "failed": "failed", "dry_run": "was checked (dry run)",
            "requested": "was requested", "unknown_outcome": "has an unknown outcome",
            "frozen": "froze every tool that changes something", "unfrozen": "was unfrozen by a human"}.get(event, event)
    return scrub_text(f"{tool}{of} {verb}" + (f": {why}" if why and event in ("blocked", "pending", "frozen", "unfrozen") else ""))


def _amount_for(ledger, policy, ev) -> float | None:
    a = ev["data"].get("amount")
    if isinstance(a, (int, float)):
        return a
    args = ev["data"].get("args")
    if isinstance(args, dict):
        rule = (policy.rule_for(ev["tool"]) if policy else None) or {}
        v = args.get(rule.get("amount_field", "amount"))
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return v
    return None


def build_report(ledger, since_ts: float, policy=None) -> dict:
    """What shadow mode saw since `since_ts`: totals and, per tool and rule, how many calls would have been blocked or held."""
    evs = [e for e in ledger.events(limit=10**7) if e["ts"] >= since_ts]
    req = {}
    for e in evs:
        if e["event"] == "requested":
            req[e["idem_key"]] = e
    shadow = [e for e in evs if e["event"] == "shadow"]
    ran = {e["idem_key"] for e in evs if e["event"] in ("executed", "read")}
    would_keys = {e["idem_key"] for e in shadow}
    rules: dict = {}
    for e in shadow:
        amt = _amount_for(ledger, policy, req.get(e["idem_key"], e) if req.get(e["idem_key"]) else e)
        seen = set()
        for r in e["data"].get("reasons") or ["(no reason recorded)"]:
            k = (e["tool"], rule_of(r), e["data"]["would"])
            if k in seen:
                continue
            seen.add(k)
            row = rules.setdefault(k, {"tool": e["tool"], "rule": k[1], "would": k[2], "count": 0, "total_amount": 0.0, "example": scrub_text(r)})
            row["count"] += 1
            row["total_amount"] += amt or 0.0
    rows = sorted(rules.values(), key=lambda r: (-r["count"], r["tool"], r["rule"]))
    blocked = sum(1 for e in shadow if e["data"]["would"] == "block")
    asked = sum(1 for e in shadow if e["data"]["would"] == "ask")
    first = min((e["ts"] for e in evs), default=None)
    last = max((e["ts"] for e in evs), default=None)
    return {"since": since_ts, "first_event": first, "last_event": last, "actions_seen": len(req), "actions_ran": len(ran),
            "would_have_blocked": blocked, "would_have_asked": asked, "unaffected": max(0, len(req) - len(would_keys)),
            "drift": _drift(ledger), "by_rule": rows, "shadow_mode_seen": bool(req) and any(r["data"].get("mode") == "shadow" for r in req.values())}


def _drift(ledger) -> list:
    """This week vs last week (see drift.py). Never lets a problem here break the report."""
    try:
        from panel_firewall.firewall import drift
        return drift.detect(ledger, time.time())
    except Exception:
        return []


def format_report(rep: dict, hours_label: str = "") -> str:
    text = _format_report(rep, hours_label)
    if rep.get("drift"):
        from panel_firewall.firewall import drift
        text += "\n\n" + drift.format_drift(rep["drift"])
    return text


def _format_report(rep: dict, hours_label: str = "") -> str:
    out = [f"Panel shadow-mode report{(' (last ' + hours_label + ')') if hours_label else ''}",
           "Shadow mode let every action run. Nothing below was actually stopped.", ""]
    if not rep["actions_seen"]:
        return "\n".join(out + ["No actions were seen in this period. Is the proxy running in front of your agent?"])
    n = rep["actions_seen"]
    out += [f"Actions your agent attempted: {n}",
            f"  would have run with no objection: {rep['unaffected']}",
            f"  would have been BLOCKED:          {rep['would_have_blocked']}",
            f"  would have needed APPROVAL:       {rep['would_have_asked']}", ""]
    if rep["by_rule"]:
        out.append("By rule (what turning enforcement on would change):")
        for r in rep["by_rule"]:
            amt = f", {_money(r['total_amount'])} in total" if r["total_amount"] else ""
            verb = "blocked" if r["would"] == "block" else "held for approval"
            out.append(f"  {r['count']:>4}x  {r['tool']}  [{r['rule']}]  {verb}{amt}")
            out.append(f"         e.g. {r['example']}")
    else:
        out.append("Nothing would have been blocked or held under this policy.")
    out += ["", "Next: if these look right, turn on enforcement by removing `--shadow` (or `mode: shadow`) from your policy. "
            "Panel never switches itself to enforcing."]
    return "\n".join(out)


def export_log(ledger, since_ts: float = 0.0, include_raw_args: bool = False, policy=None) -> list[dict]:
    """Data-minimised event log: ts, tool, event, verdict/rule, amount, scrubbed summary, receipt hashes. No raw arguments unless asked."""
    from tenthlook_core import receipt as core
    out = []
    rcpt = {}
    for e in ledger.events(limit=10**7):
        if e["event"] == "receipt" and "receipt" in e["data"]:
            rcpt[e["idem_key"]] = core.receipt_hash(e["data"]["receipt"])
    reqs = {e["idem_key"]: e for e in ledger.events(limit=10**7) if e["event"] == "requested"}
    for e in ledger.events(limit=10**7):
        if e["ts"] < since_ts or e["event"] == "receipt":
            continue
        d = e["data"]
        amount = _amount_for(ledger, policy, reqs.get(e["idem_key"], e))
        row = {"ts": e["ts"], "tool": e["tool"], "event": e["event"], "idempotency_key": e["idem_key"],
               "verdict": (d.get("verdict") or {}).get("decision") or d.get("would"),
               "rule": sorted({rule_of(r) for r in (d.get("reasons") or (d.get("verdict") or {}).get("reasons") or [])
                               if (d.get("verdict") or {}).get("decision") != "allow"}) or None,
               "amount": amount, "summary": summarize(e["tool"], e["event"], {**d, "amount": amount}),
               "action_sha256": d.get("action_sha"), "receipt_sha256": rcpt.get(e["idem_key"]) if e["event"] in ("executed", "blocked", "read") else None}
        if include_raw_args and isinstance(d.get("args"), dict):
            row["args"] = d["args"]
        out.append(row)
    return out
