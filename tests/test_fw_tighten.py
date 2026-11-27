"""`usepanel tighten`: observe -> suggest -> counterfactual replay -> accept only zero-false-positive rules, until nothing improves."""
import json

import yaml

from panel_firewall.firewall import tighten
from panel_firewall.firewall.cli import main
from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from tests.fw_helpers import FakeConnector, act, policy, signer

T0 = 1_700_000_000.0 - (1_700_000_000.0 % 86400)
RAW = {"version": "t", "mode": "shadow", "actions": {"fake.pay": {"risk": "write"}}}


def traffic(path=":memory:", extra=(), denied=(), approved=(), n=150):
    """n legitimate calls (amounts 40..60, one per minute), then outliers 90 and 200, then `extra` (amounts); `denied`/`approved` pick amounts to mark."""
    t = [T0]
    fw = Firewall(policy({"fake.pay": {"risk": "write"}}, "shadow"), Ledger(path, clock=lambda: t[0]), signer(), [FakeConnector()], clock=lambda: t[0])
    keys = {}
    for i, amt in enumerate([40 + i % 21 for i in range(n)] + [90, 200] + list(extra)):
        t[0] += 60
        keys[amt] = fw.handle(act(conv=f"c{i}", amount=amt)).idempotency_key
    for a in denied:
        fw.ledger.append(keys[a], "x", "fake.pay", "denied", {"who": "alice"})
    for a in approved:
        fw.ledger.append(keys[a], "x", "fake.pay", "approved", {"who": "alice"})
    return fw


def run(fw, raw=RAW, **kw):
    lines = []
    kw.setdefault("min_calls", 30)
    return tighten.run(fw.ledger, raw, say=lines.append, **kw), lines


def amount_rule(res):
    return res["staged"]["actions"]["fake.pay"].get("max_amount")


def test_one_productive_round_then_everything_is_covered():
    fw = traffic()
    res, lines = run(fw)
    assert res["history"] == 152 and res["anomalies"] == 2
    assert amount_rule(res) == 63 and res["stop"] == "all covered"                # legit max 60 x 1.05
    assert lines[0].startswith("Round 1: +1 rule, anomalies remaining: 2 → 0, false positives: 0")
    assert "accepted fake.pay.max_amount=63 (catches 2)" in lines[0]


def test_a_second_round_tightens_further_when_a_human_denied_a_borderline_action():
    fw = traffic(extra=[62.5], denied=[62.5])
    res, lines = run(fw)
    assert res["anomalies"] == 3
    assert [r.after for r in res["rounds"]] == [1, 0]
    assert lines[0].startswith("Round 1: +1 rule, anomalies remaining: 3 → 1")
    assert lines[1].startswith("Round 2: +1 rule, anomalies remaining: 1 → 0, false positives: 0")
    assert amount_rule(res) == 62 and res["stop"] == "all covered"                # 60 x 1.02 -> 62 now catches the denied 62.5


def test_stops_when_nothing_improves_not_when_rounds_run_out():
    fw = traffic(extra=[62.5, 62.2], denied=[62.5], approved=[62.2])
    res, lines = run(fw, max_rounds=10)
    assert res["stop"] == "irreducible" and len(res["rounds"]) < 10
    assert lines[-1].startswith(f"Round {len(res['rounds'])}: +0 rules, anomalies remaining: 1 (irreducible without intent model)")
    assert amount_rule(res) >= 62.2                                                # the approved action is never held
    final = tighten.replay(res["staged"], tighten.history(fw.ledger))
    ev = tighten.history(fw.ledger)
    approved_idx = [e.i for e in ev if e.args.get("amount") == 62.2][0]
    assert final[approved_idx] == "allow"


def test_max_rounds_is_reported_as_still_improving():
    fw = traffic(extra=[62.5], denied=[62.5])
    res, _ = run(fw, max_rounds=1)
    assert res["stop"] == "max_rounds" and len(res["rounds"]) == 1 and res["rounds"][0].after == 1


def test_a_rule_that_would_false_positive_is_rejected_and_never_staged():
    fw = traffic()
    bad = lambda *a, **k: [tighten.Candidate("fake.pay", "max_amount", 45, "too tight")]
    res, lines = run(fw, generate_fn=bad)
    assert amount_rule(res) is None and res["accepted"] == [] and res["stop"] == "irreducible"
    assert "rejected fake.pay.max_amount=45: would false-positive" in lines[0]
    assert res["rounds"][0].false_positives == 0


def test_a_rule_that_would_hold_a_previously_approved_action_is_rejected():
    fw = traffic(extra=[61.5], approved=[61.5])
    bad = lambda *a, **k: [tighten.Candidate("fake.pay", "max_amount", 61, "")]
    res, lines = run(fw, generate_fn=bad)
    assert res["accepted"] == [] and "previously approved" in lines[0]


def test_a_rule_that_catches_nothing_is_rejected():
    fw = traffic()
    res, lines = run(fw, generate_fn=lambda *a, **k: [tighten.Candidate("fake.pay", "max_amount", 5000, "")])
    assert res["accepted"] == [] and "catches no remaining anomaly" in lines[0]


def test_never_loosens_an_existing_rule_but_does_tighten_a_looser_one():
    fw = traffic()
    res, _ = run(fw, raw={**RAW, "actions": {"fake.pay": {"risk": "write", "max_amount": 55}}})
    assert amount_rule(res) == 55                                                  # 63 would loosen 55: not even proposed
    res, _ = run(fw, raw={**RAW, "actions": {"fake.pay": {"risk": "write", "max_amount": 500}}})
    assert amount_rule(res) == 63                                                  # 63 is tighter than 500
    assert tighten.tighter("max_amount", 63, 55) is None and tighten.tighter("max_amount", 63, 63) is None and tighten.tighter("max_amount", 63, 500) == 63
    assert tighten.tighter("rate_limit", {"max": 5, "per_seconds": 60}, {"max": 9, "per_seconds": 3600}) is None      # not comparable
    assert tighten.tighter("rate_limit", {"max": 5, "per_seconds": 60}, {"max": 9, "per_seconds": 60}) == {"max": 5, "per_seconds": 60}
    assert tighten.tighter("consent_sql_kinds", ["drop", "delete"], ["delete"]) == ["delete", "drop"]
    assert tighten.tighter("consent_sql_kinds", ["delete"], ["delete", "drop"]) is None


def test_every_round_is_logged_to_the_ledger_as_a_tighten_round_event():
    fw = traffic(extra=[62.5], denied=[62.5])
    res, _ = run(fw)
    evs = fw.ledger._rows("SELECT data FROM events WHERE event='tighten_round' ORDER BY seq")
    assert len(evs) == len(res["rounds"]) == 2
    d = json.loads(evs[0][0])
    assert d["round"] == 1 and d["accepted"][0]["rule"] == "max_amount" and d["anomalies_before"] == 3 and d["anomalies_after"] == 1 and d["false_positives"] == 0
    assert any(r["reason"] for r in d["rejected"]) or d["rejected"] == []


def test_the_replay_is_deterministic_and_does_not_touch_the_ledger_it_reads():
    fw = traffic()
    before = fw.ledger._rows("SELECT COUNT(*) FROM events WHERE event IN ('requested','executed')")
    ev = tighten.history(fw.ledger)
    a = tighten.replay({**RAW, "actions": {"fake.pay": {"risk": "write", "max_amount": 63}}}, ev)
    b = tighten.replay({**RAW, "actions": {"fake.pay": {"risk": "write", "max_amount": 63}}}, ev)
    assert a == b and a.count("block") == 2
    assert fw.ledger._rows("SELECT COUNT(*) FROM events WHERE event IN ('requested','executed')") == before


def test_nothing_to_tighten_without_anomalies_or_history():
    fw = traffic()
    res, _ = run(fw, min_severity=2.0)                                             # nothing reaches this severity
    assert res["stop"] == "nothing to tighten" and res["rounds"] == []
    assert tighten.run(Ledger(":memory:"), RAW, say=lambda s: None)["stop"] == "no history"


def test_cli_stages_a_valid_policy_and_never_edits_the_live_one(tmp_path, capsys):
    db = str(tmp_path / "l.sqlite")
    traffic(db, extra=[62.5], denied=[62.5])
    live = tmp_path / "policy.yaml"
    live.write_text(yaml.safe_dump(RAW))
    before = live.read_bytes()
    assert main(["tighten", "--policy", str(live), "--ledger", db, "--max-rounds", "10", "--min-calls", "30"]) == 0
    out = capsys.readouterr().out
    assert "Round 1: +1 rule, anomalies remaining: 3 → 1" in out and "Round 2: +1 rule, anomalies remaining: 1 → 0" in out
    assert "Tightening complete. 2 new rules staged in" in out and "policy.suggested.yaml" in out
    assert live.read_bytes() == before
    staged = yaml.safe_load((tmp_path / "policy.suggested.yaml").read_text())
    assert staged["actions"]["fake.pay"]["max_amount"] == 62
    from panel_firewall.firewall.policy import load_policy
    assert load_policy(tmp_path / "policy.suggested.yaml").rule_for("fake.pay")["max_amount"] == 62
    import pytest
    from panel_firewall.firewall.types import FirewallError
    with pytest.raises(FirewallError):
        tighten.write_staging(str(live), RAW, [], str(live))


def test_cli_with_nothing_to_do_writes_no_file(tmp_path, capsys):
    db = str(tmp_path / "l.sqlite")
    Ledger(db)
    live = tmp_path / "policy.yaml"
    live.write_text(yaml.safe_dump(RAW))
    assert main(["tighten", "--policy", str(live), "--ledger", db]) == 0
    assert "No requested actions" in capsys.readouterr().out and not (tmp_path / "policy.suggested.yaml").exists()
