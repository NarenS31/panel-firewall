"""Shadow-traffic baselines and a deterministic anomaly detector. Percentiles and z-scores only: no model anywhere.

Opt in with a top-level policy key:

  anomaly:
    min_calls: 100          # a tool's baseline is used only after this many executed calls (default 100)
    hold_severity: 0.8      # OPTIONAL. In enforce mode a non-read action whose anomaly severity is >= this is HELD for a human.
                            # Without it anomalies are only recorded (ledger event `anomaly`), in every mode.
    enabled: true

What is learned, per tool, from every EXECUTED action (shadow-mode runs count: they really ran), in the `baselines` table:
  amounts   the last 2000 amounts -> median, p95, p99, max, mean, std
  fields    per argument: how often present, string-length mean/std (Welford), and the set of values while it stays small (<= 20)
  hours     calls per hour (last 14 days) -> typical calls per hour
  after     which tool ran just before this one in the same conversation ("" = first in the conversation)
  gaps      seconds since the previous executed call in the same conversation (Welford mean/std)

An action is compared with the baseline BEFORE it runs. Kinds and severity (0..1, rounded to 3 places; the action's severity is the max):
  amount      amount > p99 and z >= 3            severity = clamp(0.4 + (z - 3) / 10)
  frequency   this hour's calls > 3x the mean (and >= 5)   clamp(0.4 + (ratio - 3) / 10)
  value       a never-seen value for a small-vocabulary argument     0.5
  field       an always-present argument is missing / an argument never seen before appears   0.5 / 0.4
  length      string length z >= 4                clamp(0.3 + (z - 4) / 10)
  sequence    this tool was never run right after the previous one in this conversation   0.4
  timing      gap since the previous call, |z| >= 4    clamp(0.3 + (z - 4) / 10)
Every z (with its floor on the std) and every threshold is plain arithmetic over stored numbers: the same ledger gives the same verdict.

A human can mark a flag a false positive (`usepanel learn`); that raises the z/ratio thresholds for that tool+kind (`anomaly_tuning`) or
accepts the new value/field/sequence. An anomaly never blocks; at most it HOLDS (needs_consent) when `hold_severity` is set.
Actions that were themselves flagged at or above the hold level (0.8 if unset) are NOT added to the baseline (no self-poisoning).
"""
from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass

log = logging.getLogger("panel_firewall.firewall")

DEFAULT_MIN_CALLS = 100
AMOUNT_KEEP = 2000
MAX_VALUES = 20
HOURS_KEEP = 24 * 14
KINDS = ("amount", "frequency", "value", "field", "length", "sequence", "timing")
Z_KINDS = ("amount", "frequency", "length", "timing")
POISON_FLOOR = 0.8
SCHEMA = (
    """CREATE TABLE IF NOT EXISTS baselines (tool TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS anomaly_tuning (tool TEXT NOT NULL, kind TEXT NOT NULL, bonus REAL NOT NULL, PRIMARY KEY (tool, kind))""",
)


@dataclass
class Anomaly:
    kind: str
    severity: float
    detail: str
    field: str | None = None

    def to_dict(self) -> dict:
        return {"kind": self.kind, "severity": self.severity, "detail": self.detail, "field": self.field}


# --------------------------------------------------------------------------------------------------------- config
def settings(policy) -> dict | None:
    """The `anomaly:` block (validated by policy.parse_policy), or None when the feature is off."""
    cfg = None if policy is None else policy.raw.get("anomaly")
    if cfg is None or cfg is False:
        return None
    cfg = cfg if isinstance(cfg, dict) else {}
    if cfg.get("enabled") is False:
        return None
    return {"min_calls": int(cfg.get("min_calls", DEFAULT_MIN_CALLS)), "hold_severity": cfg.get("hold_severity")}


def validate_config(raw) -> None:
    from panel_firewall.firewall.types import FirewallError
    if raw is None or isinstance(raw, bool):
        return
    if not isinstance(raw, dict) or set(raw) - {"min_calls", "hold_severity", "enabled"}:
        raise FirewallError("policy: anomaly takes only min_calls, hold_severity, enabled")
    mc = raw.get("min_calls", DEFAULT_MIN_CALLS)
    if isinstance(mc, bool) or not isinstance(mc, int) or mc < 2:
        raise FirewallError("policy: anomaly.min_calls must be an integer >= 2")
    hs = raw.get("hold_severity")
    if hs is not None and (isinstance(hs, bool) or not isinstance(hs, (int, float)) or not 0 < hs <= 1):
        raise FirewallError("policy: anomaly.hold_severity must be a number in (0, 1]")
    if "enabled" in raw and not isinstance(raw["enabled"], bool):
        raise FirewallError("policy: anomaly.enabled must be true or false")


# --------------------------------------------------------------------------------------------------------- math
def percentile(sorted_vals: list[float], p: float) -> float | None:
    """Nearest-rank percentile of an already-sorted list (deterministic, no interpolation)."""
    if not sorted_vals:
        return None
    k = max(1, math.ceil(p / 100.0 * len(sorted_vals)))
    return sorted_vals[min(k, len(sorted_vals)) - 1]


def _mean_std(vals: list[float]) -> tuple[float, float]:
    n = len(vals)
    if not n:
        return 0.0, 0.0
    m = sum(vals) / n
    return m, math.sqrt(sum((v - m) ** 2 for v in vals) / n)


def _welford(st: dict, key: str, x: float) -> None:
    n, mean, m2 = st.get(key + "_n", 0) + 1, st.get(key + "_mean", 0.0), st.get(key + "_m2", 0.0)
    d = x - mean
    mean += d / n
    m2 += d * (x - mean)
    st[key + "_n"], st[key + "_mean"], st[key + "_m2"] = n, mean, m2


def _wstd(st: dict, key: str) -> float:
    n = st.get(key + "_n", 0)
    return math.sqrt(st.get(key + "_m2", 0.0) / n) if n > 1 else 0.0


def _z(x: float, mean: float, std: float, floor_frac: float = 0.05) -> float:
    return abs(x - mean) / max(std, floor_frac * abs(mean), 1e-9)


def _clamp(x: float) -> float:
    return round(min(1.0, max(0.0, x)), 3)


def _number(v):
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) else None


# --------------------------------------------------------------------------------------------------------- store
class Baselines:
    def __init__(self, ledger):
        self.ledger = ledger
        with ledger._lock:
            for s in SCHEMA:
                ledger._db.execute(s)

    def get(self, tool: str) -> dict | None:
        r = self.ledger._rows("SELECT data FROM baselines WHERE tool=?", (tool,))
        return json.loads(r[0][0]) if r else None

    def put(self, tool: str, data: dict, now: float) -> None:
        with self.ledger._lock:
            self.ledger._db.execute("INSERT INTO baselines(tool, data, updated_at) VALUES (?,?,?) ON CONFLICT(tool) DO UPDATE SET data=excluded.data, "
                                    "updated_at=excluded.updated_at", (tool, json.dumps(data, sort_keys=True), now))

    def tools(self) -> list[str]:
        return [r[0] for r in self.ledger._rows("SELECT tool FROM baselines ORDER BY tool")]

    def bonus(self, tool: str, kind: str) -> float:
        r = self.ledger._rows("SELECT bonus FROM anomaly_tuning WHERE tool=? AND kind=?", (tool, kind))
        return float(r[0][0]) if r else 0.0

    def add_bonus(self, tool: str, kind: str, delta: float = 0.5, cap: float = 4.0) -> float:
        with self.ledger._lock:
            nb = min(cap, self.bonus(tool, kind) + delta)
            self.ledger._db.execute("INSERT INTO anomaly_tuning(tool, kind, bonus) VALUES (?,?,?) ON CONFLICT(tool, kind) DO UPDATE SET bonus=excluded.bonus",
                                    (tool, kind, nb))
            return nb


def _new_baseline() -> dict:
    return {"n": 0, "first_ts": None, "last_ts": None, "amounts": [], "fields": {}, "hours": {}, "after": {}}


def amount_of(policy, action):
    rule = (policy.rule_for(action.tool) or {}) if policy is not None else {}
    args = action.args if isinstance(action.args, dict) else {}
    return _number(args.get(rule.get("amount_field", "amount")))


def _prev_in_conversation(ledger, conv: str, exclude_key: str, now: float) -> tuple[str, float | None]:
    """(tool, ts) of the previous executed/read action in this conversation; ('', None) when it is the first."""
    r = ledger._rows("SELECT tool, ts FROM events WHERE conversation_id=? AND event IN ('executed','read') AND idem_key<>? ORDER BY seq DESC LIMIT 1",
                     (conv, exclude_key))
    return (r[0][0], r[0][1]) if r else ("", None)


def _hour(ts: float) -> str:
    return str(int(ts // 3600) * 3600)


def _scalar_key(v):
    if isinstance(v, bool):
        return str(v).lower()
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str) and len(v) <= 64:
        return v
    return None


# --------------------------------------------------------------------------------------------------------- update
def update_baseline(base: dict, args: dict, amount: float | None, prev_tool: str, gap: float | None, now: float,
                    amount_field: str = "amount") -> dict:
    base["n"] += 1
    base["first_ts"] = now if base["first_ts"] is None else base["first_ts"]
    base["last_ts"] = now
    if amount is not None:
        base["amounts"] = (base["amounts"] + [amount])[-AMOUNT_KEEP:]
    for k, v in args.items():
        if k == amount_field:
            continue
        f = base["fields"].setdefault(k, {"present": 0, "values": {}, "overflow": False})
        f["present"] += 1
        if isinstance(v, str):
            _welford(f, "len", float(len(v)))
        sk = _scalar_key(v)
        if sk is not None and not f["overflow"]:
            if sk in f["values"] or len(f["values"]) < MAX_VALUES:
                f["values"][sk] = f["values"].get(sk, 0) + 1
            else:
                f["overflow"], f["values"] = True, {}
        elif sk is None:
            f["overflow"], f["values"] = True, {}
    h = _hour(now)
    base["hours"][h] = base["hours"].get(h, 0) + 1
    if len(base["hours"]) > HOURS_KEEP:
        for old in sorted(base["hours"], key=int)[:len(base["hours"]) - HOURS_KEEP]:
            del base["hours"][old]
    base["after"][prev_tool] = base["after"].get(prev_tool, 0) + 1
    if gap is not None:
        _welford(base, "gap", gap)
    return base


def observe(policy, ledger, action, key: str, now: float) -> None:
    """Add one EXECUTED action to its tool's baseline. No-op unless `anomaly:` is configured. Never raises."""
    try:
        cfg = settings(policy)
        if cfg is None or not isinstance(action.args, dict):
            return
        cutoff = cfg["hold_severity"] if cfg["hold_severity"] is not None else POISON_FLOOR
        flagged = ledger._rows("SELECT json_extract(data,'$.severity') FROM events WHERE idem_key=? AND event='anomaly' ORDER BY seq DESC LIMIT 1", (key,))
        if flagged and flagged[0][0] is not None and float(flagged[0][0]) >= cutoff:
            return
        b = Baselines(ledger)
        with ledger._lock:
            base = b.get(action.tool) or _new_baseline()
            prev, pts = _prev_in_conversation(ledger, action.conversation_id, key, now)
            amount_field = ((policy.rule_for(action.tool) or {}).get("amount_field", "amount")) if policy is not None else "amount"
            update_baseline(base, action.args, amount_of(policy, action), prev, None if pts is None else max(0.0, now - pts), now, amount_field)
            b.put(action.tool, base, now)
    except Exception:
        log.debug("anomaly: could not update a baseline", exc_info=True)


# --------------------------------------------------------------------------------------------------------- stats
def amount_stats(base: dict) -> dict | None:
    a = sorted(base.get("amounts") or [])
    if not a:
        return None
    mean, std = _mean_std(a)
    return {"n": len(a), "median": percentile(a, 50), "p95": percentile(a, 95), "p99": percentile(a, 99), "max": a[-1], "mean": mean, "std": std}


def hourly_mean(base: dict) -> float:
    if not base["hours"]:
        return 0.0
    hs = [int(h) for h in base["hours"]]
    span = (max(hs) - min(hs)) // 3600 + 1
    return base["n"] / max(span, 1)


# --------------------------------------------------------------------------------------------------------- check
def assess(policy, ledger, action, key: str, now: float) -> list[Anomaly]:
    """Compare one not-yet-executed action with its tool's baseline. [] while the baseline is too young or the feature is off."""
    cfg = settings(policy)
    if cfg is None or not isinstance(action.args, dict):
        return []
    b = Baselines(ledger)
    base = b.get(action.tool)
    if not base or base["n"] < cfg["min_calls"]:
        return []
    mc, out = cfg["min_calls"], []
    args, tool = action.args, action.tool
    amount_field = (policy.rule_for(tool) or {}).get("amount_field", "amount")

    amt = amount_of(policy, action)
    ast = amount_stats(base)
    if amt is not None and ast and ast["n"] >= mc and amt > ast["p99"]:
        z = _z(amt, ast["mean"], ast["std"])
        if z >= 3.0 + b.bonus(tool, "amount"):
            out.append(Anomaly("amount", _clamp(0.4 + (z - 3) / 10), f"amount {amt:g} is above the p99 {ast['p99']:g} (max seen {ast['max']:g}, z={z:.1f})", amount_field))

    hm = hourly_mean(base)
    cur = ledger._rows("SELECT COUNT(*) FROM events WHERE tool=? AND event IN ('executed','read') AND ts>=?", (tool, int(now // 3600) * 3600))[0][0] + 1
    if hm > 0 and cur >= 5 and cur / hm > 3.0 + b.bonus(tool, "frequency"):
        out.append(Anomaly("frequency", _clamp(0.4 + (cur / hm - 3) / 10), f"{cur} calls this hour vs a typical {hm:.1f} ({cur / hm:.1f}x)"))

    for k, v in sorted(args.items()):
        if k == amount_field:
            continue
        f = base["fields"].get(k)
        if f is None:
            if not b.bonus(tool, "field"):
                out.append(Anomaly("field", 0.4, f"argument '{k}' was never seen in {base['n']} earlier calls", k))
            continue
        sk = _scalar_key(v)
        if sk is not None and not f["overflow"] and f["values"] and sk not in f["values"] and not b.bonus(tool, "value"):
            out.append(Anomaly("value", 0.5, f"{k}={sk!r} was never seen (usual values: {', '.join(sorted(f['values'])[:5])})", k))
        if isinstance(v, str) and f.get("len_n", 0) >= mc:
            z = _z(float(len(v)), f["len_mean"], _wstd(f, "len"), 0.25)
            if len(v) > f["len_mean"] and z >= 4.0 + b.bonus(tool, "length"):
                out.append(Anomaly("length", _clamp(0.3 + (z - 4) / 10), f"'{k}' is {len(v)} characters long vs a typical {f['len_mean']:.0f} (z={z:.1f})", k))
    if not b.bonus(tool, "field"):
        for k, f in sorted(base["fields"].items()):
            if f["present"] == base["n"] and k not in args:
                out.append(Anomaly("field", 0.5, f"argument '{k}' is present in all {base['n']} earlier calls but missing now", k))

    prev, pts = _prev_in_conversation(ledger, action.conversation_id, key, now)
    if sum(base["after"].values()) >= mc and base["after"].get(prev, 0) == 0 and not b.bonus(tool, "sequence"):
        out.append(Anomaly("sequence", 0.4, f"never run right after {prev or 'the start of a conversation'} before ({len(base['after'])} usual predecessors)"))
    if pts is not None and base.get("gap_n", 0) >= mc:
        gap = max(0.0, now - pts)
        z = _z(gap, base["gap_mean"], _wstd(base, "gap"), 0.25)
        if z >= 4.0 + b.bonus(tool, "timing"):
            out.append(Anomaly("timing", _clamp(0.3 + (z - 4) / 10), f"{gap:.1f}s after the previous call vs a typical {base['gap_mean']:.1f}s (z={z:.1f})"))
    return out


def severity(anoms: list[Anomaly]) -> float:
    return max((a.severity for a in anoms), default=0.0)


def check(policy, ledger, action, key: str, now: float) -> tuple[list[Anomaly], float]:
    """Assess and record. Writes one `anomaly` ledger event (and one learned pattern per kind) when anything is flagged. Never raises."""
    try:
        anoms = assess(policy, ledger, action, key, now)
        if not anoms:
            return [], 0.0
        sev = severity(anoms)
        ledger.append(key, action.conversation_id, action.tool, "anomaly", {"severity": sev, "anomalies": [a.to_dict() for a in anoms]})
        try:
            from panel_firewall.firewall import learn
            for a in anoms:
                learn.record_anomaly(ledger, action.tool, a, now)
        except Exception:
            log.debug("anomaly: could not record a learned pattern", exc_info=True)
        return anoms, sev
    except Exception:
        log.debug("anomaly: check failed", exc_info=True)
        return [], 0.0


def hold_reason(anoms: list[Anomaly], sev: float, threshold: float) -> str:
    top = max(anoms, key=lambda a: a.severity)
    return f"anomaly: severity {sev:g} >= {threshold:g}: {top.detail}; a human must approve"


# --------------------------------------------------------------------------------------------------------- history
def executed_calls(ledger, since_ts: float = 0.0, until_ts: float | None = None, tool: str | None = None, mode: str | None = None) -> list[dict]:
    """EXECUTED (and read) calls with their arguments: [{ts, conv, tool, args, amount}], oldest first. Source for baselines, suggestions and drift."""
    q = ("SELECT e.ts, e.conversation_id, e.tool, r.data, json_extract(e.data,'$.amount'), e.idem_key FROM events e "
         "JOIN events r ON r.idem_key = e.idem_key AND r.event = 'requested' WHERE e.event IN ('executed','read') AND e.ts > ? AND e.ts <= ?")
    a: list = [since_ts, float("inf") if until_ts is None else until_ts]
    if tool:
        q, a = q + " AND e.tool = ?", a + [tool]
    if mode:     # 'shadow' = only calls that ran while Panel was in shadow mode (the `requested` event records the mode)
        q, a = q + " AND json_extract(r.data, '$.mode') = ?", a + [mode]
    out = []
    for ts, conv, t, rd, amount, ikey in ledger._rows(q + " ORDER BY e.seq", a):
        try:
            args = json.loads(rd).get("args") or {}
        except (ValueError, AttributeError):
            args = {}
        out.append({"ts": ts, "conv": conv, "tool": t, "args": args if isinstance(args, dict) else {}, "amount": amount, "key": ikey})
    return out


def rebuild(policy, ledger, now: float) -> dict[str, int]:
    """Recompute every baseline from the ledger history (e.g. after 7 days of shadow mode). Replaces existing baselines. Returns calls per tool."""
    b, bases, last = Baselines(ledger), {}, {}
    for c in executed_calls(ledger):
        base = bases.setdefault(c["tool"], _new_baseline())
        p = last.get(c["conv"])
        rule = (policy.rule_for(c["tool"]) or {}) if policy is not None else {}
        update_baseline(base, c["args"], _number(c["amount"]), p[0] if p else "", None if not p else max(0.0, c["ts"] - p[1]), c["ts"],
                        rule.get("amount_field", "amount"))
        last[c["conv"]] = (c["tool"], c["ts"])
    for t, base in bases.items():
        b.put(t, base, now)
    return {t: base["n"] for t, base in bases.items()}


def format_baselines(ledger) -> str:
    b = Baselines(ledger)
    if not b.tools():
        return "No baselines yet. Enable `anomaly:` in the policy (or run `usepanel baseline --rebuild`) and let traffic run."
    lines = []
    for t in b.tools():
        base = b.get(t)
        st = amount_stats(base)
        s = f"{t}: {base['n']} calls, ~{hourly_mean(base):.1f}/hour"
        if st:
            s += f"; amount median {st['median']:g}, p95 {st['p95']:g}, p99 {st['p99']:g}, max {st['max']:g}"
        lines.append(s)
    return "\n".join(lines)

