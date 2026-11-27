"""`usepanel suggest`: policy rule suggestions from observed traffic. Templated YAML computed from percentiles and counts; no model.

Panel NEVER activates a suggestion. The review step writes accepted rules to a separate proposal file (`<policy>.suggested.yaml`) that a human
diffs, reviews and deploys by hand; the live policy file is not touched.

Templates (n = executed calls of the tool in the window; only tools with n >= --min-calls (default 100) get suggestions):
  max_amount         round_up(1.05 x the largest amount seen) to 2 significant figures        # observed max, p99
  rate_limit         max = ceil(1.2 x the busiest hour), per_seconds 3600
  entity_velocity    for an id-like argument (customer_id, order_id, ...) with repeated values: max_actions = the most executions any one value
                     had in one day, per_seconds 86400
  consent_sql_kinds  of [delete, drop, truncate, alter], the kinds that never appear in this tool's SQL
Rules the policy already has are not suggested again. Patterns a human marked as threats (`usepanel learn`), and patterns pushed by the
cloud threat feed (unless marked false positive), add suggestions that say where they came from.
"""
from __future__ import annotations

import copy
import math
import re
from pathlib import Path

import yaml

from panel_firewall.firewall import anomaly, learn
from panel_firewall.firewall.types import FirewallError

MIN_CALLS = 100
HEADROOM = 1.05
RATE_HEADROOM = 1.2
DANGEROUS_SQL = ("delete", "drop", "truncate", "alter")
_ID_FIELD = re.compile(r"(^id$|_id$|^(customer|user|account|order|email|recipient|payee|client)$)", re.I)
_SQL_ARGS = ("sql", "query", "statement")


def nice_up(x: float) -> float:
    """Round up to 2 significant figures: 142.5 * 1.05 = 149.6 -> 150."""
    if x <= 0:
        return 0.0
    exp = math.floor(math.log10(x)) - 1
    step = 10 ** exp
    return round(math.ceil(x / step - 1e-9) * step, 10)


def _fmt(v: float):
    return int(v) if float(v).is_integer() else round(v, 2)


def _sql_kind(s: str) -> str | None:
    m = re.match(r"\s*(?:--[^\n]*\n\s*|/\*.*?\*/\s*)*([A-Za-z]+)", s or "", re.S)
    return m.group(1).lower() if m else None


def _risk(policy, tool: str) -> str:
    return ((policy.rule_for(tool) or {}).get("risk") if policy is not None else None) or "write"


def analyze(ledger, policy, since_ts: float, min_calls: int = MIN_CALLS, from_shadow: bool = False, now: float | None = None, *,
            exclude_keys: set | None = None, ignore_existing: bool = False, headroom: float = HEADROOM, rate_headroom: float = RATE_HEADROOM) -> dict:
    """{'total': n, 'tools': {tool: {'n', 'rules': {...}, 'notes': {rule: comment}}}, 'sources': {tool: [why...]}, 'info': [...]}."""
    calls = anomaly.executed_calls(ledger, since_ts, mode="shadow" if from_shadow else None)
    by_tool: dict[str, list[dict]] = {}
    for c in calls:
        if exclude_keys and c.get("key") in exclude_keys:
            continue
        by_tool.setdefault(c["tool"], []).append(c)
    out = {"total": len(calls), "tools": {}, "sources": {}, "info": [], "skipped": {}}
    for tool, cs in sorted(by_tool.items()):
        if len(cs) < min_calls:
            out["skipped"][tool] = len(cs)
            continue
        have = {} if ignore_existing else ((policy.rule_for(tool) or {}) if policy is not None else {})
        rules, notes = {}, {}
        amts = sorted(c["amount"] for c in cs if isinstance(c["amount"], (int, float)))
        if amts and "max_amount" not in have:
            mx = amts[-1]
            rules["max_amount"] = _fmt(nice_up(mx * headroom))
            notes["max_amount"] = f"observed max was {_fmt(mx)}, p99 was {_fmt(anomaly.percentile(amts, 99))}"
        if _risk(policy, tool) != "read":
            hours: dict[int, int] = {}
            for c in cs:
                hours[int(c["ts"] // 3600)] = hours.get(int(c["ts"] // 3600), 0) + 1
            peak = max(hours.values())
            if "rate_limit" not in have:
                rules["rate_limit"] = {"max": max(peak + 1, math.ceil(peak * rate_headroom - 1e-9)), "per_seconds": 3600}
                notes["rate_limit"] = f"observed max was {peak}/hour"
            if "entity_velocity" not in have:
                best = None
                for fld in sorted({k for c in cs for k in c["args"]}):
                    if not _ID_FIELD.search(fld):
                        continue
                    vals = [(str(c["args"][fld]), int(c["ts"] // 86400)) for c in cs if fld in c["args"] and isinstance(c["args"][fld], (str, int))]
                    if len({v for v, _d in vals}) < 2:
                        continue
                    per: dict[tuple, int] = {}
                    for k in vals:
                        per[k] = per.get(k, 0) + 1
                    mx = max(per.values())
                    if mx < 1000 and (best is None or len(vals) > best[2]):
                        best = (fld, mx, len(vals))
                if best:
                    rules["entity_velocity"] = {"field": best[0], "max_actions": best[1], "per_seconds": 86400}
                    notes["entity_velocity"] = f"no {best[0]} was acted on more than {best[1]} time(s) in a day"
        fld = (have.get("sql_arg") if have else None) or next((a for a in _SQL_ARGS if any(a in c["args"] for c in cs)), None)
        if fld and "consent_sql_kinds" not in have:
            seen = {_sql_kind(str(c["args"].get(fld, ""))) for c in cs}
            never = [k for k in DANGEROUS_SQL if k not in seen]
            if never:
                rules["consent_sql_kinds"] = never
                notes["consent_sql_kinds"] = "never observed in normal traffic"
        if rules:
            out["tools"][tool] = {"n": len(cs), "rules": rules, "notes": notes}
    _from_patterns(ledger, policy, out, by_tool, min_calls)
    return out


def _from_patterns(ledger, policy, out: dict, by_tool: dict, min_calls: int) -> None:
    """Add rules for human-confirmed threats and for cloud-reported patterns (never for patterns marked false positive)."""
    b = anomaly.Baselines(ledger)
    for p in learn.patterns(ledger):
        if p["status"] == "false_positive" or (p["status"] == "unconfirmed" and p["source"] != "cloud"):
            continue
        origin = "confirmed as a threat" if p["status"] == "threat" else "reported by the cloud threat feed (unconfirmed)"
        tools = [p["tool"]] if p["tool"] else sorted(t for t in by_tool if _category(t) == p["category"])
        for tool in tools:
            have = (policy.rule_for(tool) or {}) if policy is not None else {}
            base = b.get(tool)
            rule = None
            if p["pattern_type"] in ("amount_outlier", "cap_split") and base and "consent_over_amount" not in have:
                st = anomaly.amount_stats(base)
                if st:
                    rule = ("consent_over_amount", _fmt(nice_up(st["p99"])), f"p99 of {st['n']} calls, from pattern {p['id']}")
            elif p["pattern_type"] in ("frequency_spike", "velocity_burst") and base and "rate_limit" not in have:
                hm = anomaly.hourly_mean(base)
                if hm > 0:
                    rule = ("rate_limit", {"max": max(2, math.ceil(3 * hm)), "per_seconds": 3600}, f"3x the typical {hm:.1f}/hour, from pattern {p['id']}")
            elif p["pattern_type"] == "sql_injection" and "consent_sql_kinds" not in have:
                rule = ("consent_sql_kinds", list(DANGEROUS_SQL), f"from pattern {p['id']}")
            if rule is None:
                out["info"].append(f"{learn.describe(p)}: {origin}; no single policy rule expresses it. Consider `anomaly.hold_severity`.")
                continue
            ent = out["tools"].setdefault(tool, {"n": len(by_tool.get(tool, [])), "rules": {}, "notes": {}})
            if rule[0] not in ent["rules"]:
                ent["rules"][rule[0]] = rule[1]
                ent["notes"][rule[0]] = f"{origin}: {rule[2]}"
            out["sources"].setdefault(tool, []).append(origin)


def _category(tool: str) -> str:
    from panel_firewall.firewall.telemetry import tool_category
    return tool_category(tool)


# ----------------------------------------------------------------------------------------------------- output
def _rule_lines(name: str, val, note: str, indent: str = "    ") -> list[str]:
    if isinstance(val, dict):
        first = f"{indent}{name}:"
        lines = [first + (f"    # {note}" if note else "")]
        lines += [f"{indent}  {k}: {v}" for k, v in val.items()]
        return lines
    v = "[" + ", ".join(val) + "]" if isinstance(val, list) else str(val)
    return [f"{indent}{name}: {v}".ljust(34) + (f"# {note}" if note else "")]


def format_suggestions(res: dict, since: str = "7d", from_shadow: bool = True) -> str:
    head = f"Suggested rules based on {since} of {'shadow mode ' if from_shadow else ''}traffic ({res['total']:,} tool calls):"
    if not res["tools"] and not res["info"]:
        extra = "".join(f"\n  {t}: only {n} calls (need more)" for t, n in sorted(res["skipped"].items()))
        return head + "\n\n  No suggestions: nothing stands out yet, or the policy already covers it." + extra
    lines = [head, ""]
    for tool, ent in res["tools"].items():
        lines.append(f"  {tool}:" + (f"    # {'; '.join(sorted(set(res['sources'][tool])))}" if tool in res["sources"] else ""))
        for name, val in ent["rules"].items():
            lines += _rule_lines(name, val, ent["notes"].get(name, ""))
        lines.append("")
    for i in res["info"]:
        lines.append(f"  note: {i}")
    for t, n in sorted(res["skipped"].items()):
        lines.append(f"  ({t}: only {n} calls, too few to suggest anything)")
    return "\n".join(lines).rstrip()


def merge(raw_policy: dict, accepted: dict[str, dict]) -> dict:
    """A copy of the policy with the accepted rules added (existing keys are never overwritten). Pure."""
    out = copy.deepcopy(raw_policy)
    acts = out.setdefault("actions", {})
    for tool, rules in accepted.items():
        r = acts.setdefault(tool, {})
        for k, v in rules.items():
            r.setdefault(k, v)
    return out


def write_proposal(policy_path: str, raw_policy: dict, accepted: dict[str, dict], out_path: str | None = None) -> Path:
    from panel_firewall.firewall.policy import parse_policy
    merged = merge(raw_policy, accepted)
    parse_policy(merged)     # the proposal must be a valid policy
    p = Path(out_path) if out_path else Path(policy_path).with_suffix(".suggested.yaml")
    if p.resolve() == Path(policy_path).resolve():
        raise FirewallError("refusing to overwrite the live policy: suggestions go to a separate proposal file")
    p.write_text("# PROPOSAL generated by `usepanel suggest`. Review it, diff it against the live policy, then deploy it yourself.\n"
                 + yaml.safe_dump(merged, sort_keys=False))
    return p


def review(res: dict, ask) -> dict[str, dict]:
    """Interactive choice. `ask(prompt) -> str`. Returns {tool: {rule: value}} of the accepted rules ({} for skip)."""
    choice = ask("Accept these rules? [review each / accept all / skip] ").strip().lower()
    if choice.startswith("a"):
        return {t: dict(e["rules"]) for t, e in res["tools"].items()}
    if not choice.startswith("r"):
        return {}
    accepted: dict[str, dict] = {}
    for tool, ent in res["tools"].items():
        for name, val in ent["rules"].items():
            if ask(f"  {tool}: {name} = {val}   accept? [y/N] ").strip().lower().startswith("y"):
                accepted.setdefault(tool, {})[name] = val
    return accepted
