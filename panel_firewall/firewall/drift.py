"""Baseline drift: compare this week's traffic with last week's. Runs inside `usepanel report`. Plain arithmetic over ledger history.

For each tool, with at least MIN_CALLS executed calls in BOTH weeks (a tool new this week is reported as new):
  amount     the average amount moved by >= 50%
  frequency  calls this week >= 2x last week (or <= half)
  values     a small-vocabulary argument (<= 20 distinct values last week) shows values it never had
  sql        SQL statements, normalised (literals -> ?), that were not in last week's set
  new tool   called this week, never last week
"""
from __future__ import annotations

import re

from panel_firewall.firewall import anomaly

WEEK = 7 * 86400.0
MIN_CALLS = 10
AMOUNT_SHIFT = 0.5
SQL_ARGS = ("sql", "query", "statement")


def normalise_sql(s: str) -> str:
    s = re.sub(r"'(?:[^']|'')*'", "?", s)
    s = re.sub(r"\b\d+(?:\.\d+)?\b", "?", s)
    return re.sub(r"\s+", " ", s).strip().lower()


def _money(v: float) -> str:
    return f"${v:,.2f}".replace(".00", "")


def compare(this: list[dict], prior: list[dict], min_calls: int = MIN_CALLS) -> list[dict]:
    """Findings: [{'tool', 'kind', 'text'}]. Pure."""
    def group(cs):
        g: dict[str, list[dict]] = {}
        for c in cs:
            g.setdefault(c["tool"], []).append(c)
        return g
    a, b = group(this), group(prior)
    out = []
    for tool in sorted(a):
        cur = a[tool]
        if tool not in b:
            out.append({"tool": tool, "kind": "new_tool", "text": f"{tool}: new tool, called {len(cur)} time(s) this week and not at all last week"})
            continue
        old = b[tool]
        if len(cur) < min_calls or len(old) < min_calls:
            continue
        ca, oa = [c["amount"] for c in cur if isinstance(c["amount"], (int, float))], [c["amount"] for c in old if isinstance(c["amount"], (int, float))]
        if len(ca) >= min_calls and len(oa) >= min_calls:
            m1, m0 = sum(ca) / len(ca), sum(oa) / len(oa)
            if m0 > 0 and abs(m1 - m0) / m0 >= AMOUNT_SHIFT:
                pct = (m1 - m0) / m0 * 100
                out.append({"tool": tool, "kind": "amount", "text": f"{tool}: average amount shifted from {_money(m0)} to {_money(m1)} "
                                                                    f"({abs(pct):.0f}% {'increase' if pct > 0 else 'decrease'})"})
        if len(cur) >= 2 * len(old) or 2 * len(cur) <= len(old):
            out.append({"tool": tool, "kind": "frequency", "text": f"{tool}: call volume went from {len(old)} to {len(cur)} ({len(cur) / len(old):.1f}x)"})
        for fld in sorted({k for c in old for k in c["args"]}):
            ov = {str(c["args"][fld]) for c in old if fld in c["args"] and isinstance(c["args"][fld], (str, int, float, bool)) and len(str(c["args"][fld])) <= 64}
            if not ov or len(ov) > anomaly.MAX_VALUES or fld in SQL_ARGS:
                continue
            nv = {str(c["args"][fld]) for c in cur if fld in c["args"] and isinstance(c["args"][fld], (str, int, float, bool))} - ov
            if nv:
                out.append({"tool": tool, "kind": "values", "text": f"{tool}: {len(nv)} new value(s) for '{fld}' not seen before ({', '.join(sorted(nv)[:3])})"})
        for fld in SQL_ARGS:
            os_ = {normalise_sql(str(c["args"][fld])) for c in old if isinstance(c["args"].get(fld), str)}
            ns = {normalise_sql(str(c["args"][fld])) for c in cur if isinstance(c["args"].get(fld), str)} - os_
            if os_ and ns:
                out.append({"tool": tool, "kind": "sql", "text": f"{tool}: {len(ns)} new SQL pattern(s) not seen in the prior baseline"})
    return out


def detect(ledger, now: float, min_calls: int = MIN_CALLS) -> list[dict]:
    this = anomaly.executed_calls(ledger, now - WEEK, now)
    prior = anomaly.executed_calls(ledger, now - 2 * WEEK, now - WEEK)
    return compare(this, prior, min_calls)


def format_drift(findings: list[dict]) -> str:
    if not findings:
        return ""
    lines = ["Baseline drift detected:"] + [f"  {f['text']}" for f in findings]
    lines.append("  Recommendation: review policy rules and run `usepanel suggest`")
    return "\n".join(lines)
