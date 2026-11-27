"""`usepanel tighten`: repeat observe -> suggest -> test until no rule can improve the catch rate without a false positive. No model anywhere.

One round:
  1. take the last N (default 500) requested actions from the ledger and label them (below)
  2. generate candidate rules from the LEGITIMATE traffic only (suggest.analyze, same templates as `usepanel suggest`); a candidate must be
     strictly tighter than what the staged policy already has (an existing rule is never loosened)
  3. dry-run each candidate against the history: a COUNTERFACTUAL REPLAY of every action, in order, through a real Firewall with an in-memory
     ledger and the candidate policy (so rate limits, velocity and cumulative caps see the state the candidate would have created)
  4. accept a candidate iff it newly holds/blocks >= 1 still-uncaught anomaly, newly holds/blocks 0 legitimate actions, and touches 0
     human-approved actions. Accepted rules go into the staged policy at once, so the next candidate is scored against it.
  5. re-score the remaining anomalies against the staged policy; start the next round with a tighter headroom (amount 1.05 -> 1.02, rate 1.2 -> 1.1 -> 1.02,
     never below --min-headroom).
Stops when a round accepts nothing (irreducible), when no anomaly remains, or at --max-rounds (reported as "still improving").

Labels. ANOMALY: flagged by the statistical detector (anomaly.py, replayed in order over the same history, severity >= --min-severity), or
flagged live in the ledger, or denied by a human. LEGITIMATE: everything else, and always anything a human approved. An action the staged policy
already holds or blocks is "already caught" and not counted as remaining.
The live policy is never touched: the result is written to <policy>.suggested.yaml, and every round is logged to the ledger as `tighten_round`.
"""
from __future__ import annotations

import copy
import json
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from panel_firewall.firewall import anomaly, suggest
from panel_firewall.firewall.connector import Connector
from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from panel_firewall.firewall.policy import parse_policy
from panel_firewall.firewall.receipts import Signer, generate_key
from panel_firewall.firewall.types import Action, ActionSchema, FirewallError, Result, sha256_hex

HISTORY = 500
AMOUNT_LADDER = (1.05, 1.02)
RATE_LADDER = (1.2, 1.1, 1.02)
RANK = {"allow": 0, "consent": 1, "block": 2}
_DROP_KEYS = ("circuit_breaker", "telemetry", "anomaly", "enforce_mode", "consent_wait_seconds")
_signer: Signer | None = None


@dataclass
class Event:
    i: int
    ts: float
    key: str
    conv: str
    tool: str
    args: dict


@dataclass
class Candidate:
    tool: str
    rule: str
    value: object
    note: str = ""

    def label(self) -> str:
        v = json.dumps(self.value) if isinstance(self.value, (dict, list)) else self.value
        return f"{self.tool}.{self.rule}={v}"


@dataclass
class RoundResult:
    n: int
    accepted: list = field(default_factory=list)       # [(Candidate, caught, [event idx])]
    rejected: list = field(default_factory=list)       # [(Candidate, reason)]
    before: int = 0
    after: int = 0
    false_positives: int = 0


# --------------------------------------------------------------------------------------------------------- replay
def _get_signer() -> Signer:
    global _signer
    if _signer is None:
        d = Path(tempfile.mkdtemp(prefix="panel-tighten-"))     # a throwaway key: replay receipts are never kept or verified
        _signer = Signer.load(generate_key(d / "k.pem"))
    return _signer


class _Replay(Connector):
    name = "replay"

    def __init__(self, tools: dict[str, str]):
        self.tools = tools

    def describe_actions(self):
        return [ActionSchema(t, t, {}, (), r) for t, r in self.tools.items()]

    def execute(self, action, mode):
        return Result(True, "replay", None)


def history(ledger, n: int = HISTORY) -> list[Event]:
    """The last n distinct requested actions, oldest first."""
    rows = ledger._rows("SELECT seq, ts, idem_key, conversation_id, tool, data FROM events WHERE event='requested' ORDER BY seq DESC LIMIT ?", (n * 3,))
    seen, out = set(), []
    for seq, ts, key, conv, tool, data in sorted(rows):
        if key in seen:
            continue
        try:
            args = json.loads(data).get("args")
        except ValueError:
            continue
        if isinstance(args, dict):
            seen.add(key)
            out.append(Event(0, ts, key, conv, tool, args))
    out = out[-n:]
    for i, e in enumerate(out):
        e.i = i
    return out


def _clean(raw: dict) -> dict:
    r = copy.deepcopy(raw)
    for k in _DROP_KEYS:
        r.pop(k, None)
    r["mode"] = "auto"
    return r


def _tools(raw: dict, events: list[Event]) -> dict[str, str]:
    acts = raw.get("actions") or {}
    return {t: (acts[t].get("risk") or "write") for t in acts}


def replay(raw: dict, events: list[Event]) -> list[str]:
    """Verdict class ('allow' | 'consent' | 'block') of every event under this policy. Deterministic: same inputs, same list."""
    raw = _clean(raw)
    pol = parse_policy(raw, sha256_hex(json.dumps(raw, sort_keys=True, default=str)))
    now = [events[0].ts if events else 0.0]
    fw = Firewall(pol, Ledger(":memory:", clock=lambda: now[0]), _get_signer(), [_Replay(_tools(raw, events))], mode="auto", clock=lambda: now[0])
    out = []
    for e in events:
        now[0] = e.ts
        o = fw.handle(Action(e.tool, copy.deepcopy(e.args), e.conv, f"replay-{e.i}"))
        out.append("allow" if o.status in ("executed", "replayed") else "consent" if o.status == "needs_consent" else "block")
    return out


def label(ledger, raw: dict, events: list[Event], min_calls: int, min_severity: float) -> tuple[set[int], set[int]]:
    """(anomalous event indexes, human-approved event indexes)."""
    acts = {}
    for t, r in (raw.get("actions") or {}).items():
        acts[t] = {k: v for k, v in r.items() if k in ("risk", "amount_field")}
    lab = {"version": "tighten-label", "mode": "shadow", "actions": acts, "anomaly": {"min_calls": min_calls}}
    pol = parse_policy(lab, "0" * 64)
    now = [events[0].ts if events else 0.0]
    led = Ledger(":memory:", clock=lambda: now[0])
    fw = Firewall(pol, led, _get_signer(), [_Replay(_tools(lab, events))], mode="shadow", clock=lambda: now[0])
    for e in events:
        now[0] = e.ts
        fw.handle(Action(e.tool, copy.deepcopy(e.args), e.conv, f"replay-{e.i}"))
    by_key = {f"k:replay-{e.i}": e.i for e in events}
    anomalous = {by_key[k] for k, sev in led._rows("SELECT idem_key, MAX(json_extract(data,'$.severity')) FROM events WHERE event='anomaly' GROUP BY idem_key")
                 if k in by_key and sev is not None and sev >= min_severity}
    idx = {e.key: e.i for e in events}
    for (k, sev) in ledger._rows("SELECT idem_key, MAX(json_extract(data,'$.severity')) FROM events WHERE event='anomaly' GROUP BY idem_key"):
        if k in idx and sev is not None and sev >= min_severity:
            anomalous.add(idx[k])
    anomalous |= {idx[k] for (k,) in ledger._rows("SELECT DISTINCT idem_key FROM events WHERE event='denied'") if k in idx}
    approved = {idx[k] for (k,) in ledger._rows("SELECT DISTINCT idem_key FROM events WHERE event='approved'") if k in idx}
    return anomalous - approved, approved


# --------------------------------------------------------------------------------------------------------- candidates
def tighter(rule: str, new, old):
    """The value to stage if `new` is strictly tighter than `old` (None when it would loosen, equal, or cannot be compared)."""
    if old is None:
        return new
    if rule in ("max_amount", "consent_over_amount"):
        return new if isinstance(old, (int, float)) and new < old else None
    if rule == "rate_limit" and isinstance(old, dict):
        return new if old.get("per_seconds") == new["per_seconds"] and new["max"] < old.get("max", 0) else None
    if rule == "entity_velocity" and isinstance(old, dict):
        same = old.get("field") == new["field"] and old.get("per_seconds") == new["per_seconds"]
        return new if same and new["max_actions"] < old.get("max_actions", 0) else None
    if rule == "consent_sql_kinds" and isinstance(old, list):
        extra = [k for k in new if k not in old]
        return list(old) + extra if extra else None
    return None


def generate(ledger, staged: dict, events: list[Event], legit_keys: set[str], min_calls: int, round_n: int, min_headroom: float) -> list[Candidate]:
    amount_h = max(min_headroom, AMOUNT_LADDER[min(round_n - 1, len(AMOUNT_LADDER) - 1)])
    rate_h = max(min_headroom, RATE_LADDER[min(round_n - 1, len(RATE_LADDER) - 1)])
    pol = parse_policy(_clean(staged), "0" * 64)
    excl = {e.key for e in events} - set(legit_keys)          # derive thresholds from legitimate calls only
    res = suggest.analyze(ledger, pol, (events[0].ts - 1) if events else 0.0, min_calls, exclude_keys=excl, ignore_existing=True,
                          headroom=amount_h, rate_headroom=rate_h)
    out = []
    acts = staged.get("actions") or {}
    for tool, ent in sorted(res["tools"].items()):
        for rule, val in sorted(ent["rules"].items()):
            new = tighter(rule, val, (acts.get(tool) or {}).get(rule))
            if new is not None:
                out.append(Candidate(tool, rule, new, ent["notes"].get(rule, "")))
    return out


def apply(staged: dict, c: Candidate) -> dict:
    r = copy.deepcopy(staged)
    r.setdefault("actions", {}).setdefault(c.tool, {})[c.rule] = c.value
    return r


# --------------------------------------------------------------------------------------------------------- scoring
def score(staged: dict, base: list[str], c: Candidate, events: list[Event], anomalies: set[int], approved: set[int]) -> dict:
    """What the candidate changes, relative to the staged policy. `caught`: still-uncaught anomalies it newly holds/blocks."""
    cand = replay(apply(staged, c), events)
    worse = [e.i for e in events if RANK[cand[e.i]] > RANK[base[e.i]]]
    caught = [i for i in worse if i in anomalies and base[i] == "allow"]
    fp = [i for i in worse if i not in anomalies]
    return {"verdicts": cand, "caught": caught, "false_positives": fp, "approved_hit": [i for i in worse if i in approved]}


def judge(s: dict) -> str | None:
    """None = accept; otherwise the reason it is rejected."""
    if s["approved_hit"]:
        return f"would hold {len(s['approved_hit'])} previously approved action(s)"
    if s["false_positives"]:
        return f"would false-positive {len(s['false_positives'])} legitimate action(s)"
    if not s["caught"]:
        return "catches no remaining anomaly"
    return None


def remaining(base: list[str], anomalies: set[int]) -> int:
    return sum(1 for i in anomalies if base[i] == "allow")


# --------------------------------------------------------------------------------------------------------- the loop
def run(ledger, raw_policy: dict, *, max_rounds: int = 10, n_history: int = HISTORY, min_calls: int = anomaly.DEFAULT_MIN_CALLS,
        min_severity: float = 0.4, min_headroom: float = 1.02, say=print, now: float | None = None, generate_fn=None) -> dict:
    """Returns {'staged': policy dict, 'accepted': [...], 'rounds': [...], 'history': n, 'anomalies': n, 'stop': reason}. Writes tighten_round events."""
    events = history(ledger, n_history)
    run_id = sha256_hex(f"{time.time()}{len(events)}")[:8]
    staged = copy.deepcopy(raw_policy)
    out = {"staged": staged, "accepted": [], "rounds": [], "history": len(events), "anomalies": 0, "stop": ""}
    if not events:
        out["stop"] = "no history"
        return out
    anomalies, approved = label(ledger, raw_policy, events, min_calls, min_severity)
    out["anomalies"] = len(anomalies)
    legit_keys = {e.key for e in events if e.i not in anomalies}
    base = replay(staged, events)
    left = remaining(base, anomalies)
    if not left:
        out["stop"] = "nothing to tighten"
        return out
    gen = generate_fn or generate
    for n in range(1, max_rounds + 1):
        rr = RoundResult(n, before=left)
        for c in gen(ledger, staged, events, legit_keys, min_calls, n, min_headroom):
            s = score(staged, base, c, events, anomalies, approved)
            why = judge(s)
            if why:
                rr.rejected.append((c, why))
                continue
            staged = apply(staged, c)
            base = s["verdicts"]
            rr.accepted.append((c, len(s["caught"]), s["caught"]))
        left = remaining(base, anomalies)
        rr.after = left
        original = replay(raw_policy, events)
        rr.false_positives = sum(1 for e in events if e.i not in anomalies and RANK[base[e.i]] > RANK[original[e.i]])
        out["rounds"].append(rr)
        out["accepted"] += [a[0] for a in rr.accepted]
        ledger.append(f"tighten:{run_id}:{n}", "tighten", "tighten", "tighten_round", {
            "round": n, "accepted": [{"tool": c.tool, "rule": c.rule, "value": c.value, "caught": k} for c, k, _ in rr.accepted],
            "rejected": [{"tool": c.tool, "rule": c.rule, "value": c.value, "reason": w} for c, w in rr.rejected],
            "anomalies_before": rr.before, "anomalies_after": rr.after, "false_positives": rr.false_positives, "history": len(events)})
        say(format_round(rr))
        if not rr.accepted:
            out["stop"] = "irreducible"
            break
        if left == 0:
            out["stop"] = "all covered"
            break
    else:
        out["stop"] = "max_rounds"
    out["staged"] = staged
    return out


def format_round(rr: RoundResult) -> str:
    k = len(rr.accepted)
    if not k:
        extra = f"anomalies remaining: {rr.after}" + (" (irreducible without intent model)" if rr.after else "")
        s = f"Round {rr.n}: +0 rules, {extra}"
    else:
        s = f"Round {rr.n}: +{k} rule{'s' if k != 1 else ''}, anomalies remaining: {rr.before} → {rr.after}, false positives: {rr.false_positives}"
    for c, why in rr.rejected:
        s += f"\n    rejected {c.label()}: {why}"
    for c, caught, _ in rr.accepted:
        s += f"\n    accepted {c.label()} (catches {caught})"
    return s


def write_staging(policy_path: str, staged: dict, accepted: list, out_path: str | None = None) -> Path:
    parse_policy(staged, "0" * 64)       # the staging file must be a valid policy
    p = Path(out_path) if out_path else Path(policy_path).with_suffix(".suggested.yaml")
    if p.resolve() == Path(policy_path).resolve():
        raise FirewallError("refusing to overwrite the live policy: tightened rules go to a separate staging file")
    head = ["# STAGING policy generated by `usepanel tighten`. Panel does not use it. Review it, diff it against the live policy, merge it yourself."]
    head += [f"# {c.label()}  ({c.note})" if c.note else f"# {c.label()}" for c in accepted]
    p.write_text("\n".join(head) + "\n" + yaml.safe_dump(staged, sort_keys=False))
    return p
