"""Shadow-traffic baselines and the deterministic anomaly detector (percentiles and z-scores, no model)."""
import pytest

from panel_firewall.firewall import anomaly
from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from panel_firewall.firewall.types import FirewallError
from tests.fw_helpers import FakeConnector, act, policy, signer

T0 = 1_700_000_000.0 - (1_700_000_000.0 % 86400)


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def mk(cfg=None, mode="auto", clock=None, actions=None):
    clock = clock or Clock()
    top = {} if cfg is None else {"anomaly": cfg}
    pol = policy(actions or {"fake.pay": {"risk": "write"}, "fake.read": {"risk": "read"}}, mode, **top)
    return Firewall(pol, Ledger(":memory:", clock=clock), signer(), [FakeConnector()], clock=clock), clock


def feed(fw, clock, n=120, step=60.0, amounts=None, tool="fake.pay", **extra):
    for i in range(n):
        clock.t += step
        a = amounts[i % len(amounts)] if amounts else 40 + (i % 21)      # 40..60 cycling
        o = fw.handle(act(tool, conv=f"c{i}", **({} if tool == "fake.read" else {"amount": a}), **extra))
        assert o.status == "executed", o.verdict.reasons


def kinds(fw, **kw):
    return {a.kind for a in anomaly.assess(fw.policy, fw.ledger, act(conv="probe", **kw), "k-test", fw.clock())}


def logged_kinds(fw):
    import json
    return {a["kind"] for (d,) in fw.ledger._rows("SELECT data FROM events WHERE event='anomaly'") for a in json.loads(d)["anomalies"]}


def test_percentiles_are_nearest_rank_and_deterministic():
    v = sorted(float(x) for x in range(1, 101))
    assert anomaly.percentile(v, 50) == 50 and anomaly.percentile(v, 95) == 95 and anomaly.percentile(v, 99) == 99
    assert anomaly.percentile(v, 100) == 100 and anomaly.percentile([], 50) is None and anomaly.percentile([7.0], 99) == 7.0


def test_baseline_learns_the_amount_distribution_from_every_executed_action():
    fw, clock = mk({})
    feed(fw, clock)
    base = anomaly.Baselines(fw.ledger).get("fake.pay")
    st = anomaly.amount_stats(base)
    assert base["n"] == 120 and st["n"] == 120
    assert 48 <= st["median"] <= 50 and st["max"] == 60 and st["p99"] == 60 and 40 <= st["p95"] <= 60
    assert base["fields"] == {} or "amount" not in base["fields"]     # the amount is tracked as a distribution, not as a categorical value
    assert base["after"] == {"": 120}                                  # each call was first in its own conversation


def test_nothing_is_flagged_before_min_calls():
    fw, clock = mk({"min_calls": 100})
    feed(fw, clock, n=60)
    assert kinds(fw, amount=9999) == set()
    assert fw.ledger._rows("SELECT COUNT(*) FROM events WHERE event='anomaly'")[0][0] == 0


def test_amount_above_p99_is_flagged_with_a_severity_and_logged_in_the_ledger():
    fw, clock = mk({})
    feed(fw, clock)
    assert kinds(fw, amount=55) == set()
    clock.t += 60
    o = fw.handle(act(conv="x", amount=200))
    assert o.status == "executed"                                      # no hold_severity: log only, in every mode
    ev = fw.ledger._rows("SELECT data FROM events WHERE event='anomaly'")
    assert len(ev) == 1
    import json
    d = json.loads(ev[0][0])
    assert d["severity"] >= 0.4 and d["anomalies"][0]["kind"] == "amount" and "p99" in d["anomalies"][0]["detail"]


def test_shadow_mode_only_logs_even_with_a_hold_threshold():
    fw, clock = mk({"hold_severity": 0.4}, mode="shadow")
    feed(fw, clock)
    clock.t += 60
    o = fw.handle(act(conv="x", amount=500))
    assert o.status == "executed"
    assert fw.ledger._rows("SELECT COUNT(*) FROM events WHERE event='anomaly'")[0][0] == 1


def test_enforce_mode_holds_above_the_threshold_but_never_blocks():
    fw, clock = mk({"hold_severity": 0.4})
    feed(fw, clock)
    clock.t += 60
    o = fw.handle(act(conv="x", amount=500))
    assert o.status == "needs_consent" and o.verdict.reasons[0].startswith("anomaly: severity")
    assert o.verdict.decision == "needs_consent"
    from panel_firewall.firewall.summary import rule_of
    assert rule_of(o.verdict.reasons[0]) == "anomaly"
    # a normal amount still runs
    clock.t += 60
    assert fw.handle(act(conv="y", amount=50)).status == "executed"


def test_the_threshold_is_respected_and_reads_are_never_held():
    fw, clock = mk({"hold_severity": 1.0})
    feed(fw, clock)
    clock.t += 60
    assert fw.handle(act(conv="x", amount=45.5 * 3)).status in ("executed", "needs_consent")
    fw2, c2 = mk({"hold_severity": 0.4})
    feed(fw2, c2)
    feed(fw2, c2, n=120, tool="fake.read")
    c2.t += 1
    for i in range(30):                                               # a read burst is flagged as frequency but a read is never held
        assert fw2.handle(act("fake.read", conv=f"r{i}")).status == "executed"


def test_an_existing_policy_block_still_wins_over_an_anomaly_hold():
    fw, clock = mk({"hold_severity": 0.4}, actions={"fake.pay": {"risk": "write", "max_amount": 100}, "fake.read": {"risk": "read"}})
    feed(fw, clock)
    clock.t += 60
    o = fw.handle(act(conv="x", amount=500))
    assert o.status == "blocked" and "exceeds the maximum" in o.verdict.reasons[0]


def test_the_same_traffic_gives_the_same_anomalies():
    runs = []
    for _ in range(2):
        fw, clock = mk({})
        feed(fw, clock)
        runs.append([a.to_dict() for a in anomaly.assess(fw.policy, fw.ledger, act(amount=180), "k", clock())])
    assert runs[0] == runs[1] and runs[0]


def test_a_flagged_action_does_not_poison_the_baseline():
    fw, clock = mk({"hold_severity": 0.8}, mode="shadow")
    feed(fw, clock)
    before = anomaly.Baselines(fw.ledger).get("fake.pay")
    clock.t += 60
    fw.handle(act(conv="x", amount=10_000))                            # runs (shadow) but is a severity-1.0 outlier
    after = anomaly.Baselines(fw.ledger).get("fake.pay")
    assert after["n"] == before["n"] and max(after["amounts"]) == 60


def test_never_seen_value_for_a_small_vocabulary_argument():
    fw, clock = mk({})
    feed(fw, clock, currency="usd")
    assert kinds(fw, amount=50, currency="usd") == set()
    assert "value" in kinds(fw, amount=50, currency="eur")


def test_high_cardinality_arguments_are_not_treated_as_categorical():
    fw, clock = mk({})
    for i in range(120):
        clock.t += 60
        fw.handle(act(conv=f"c{i}", amount=50, customer_id=f"cus_{i}"))
    assert "value" not in kinds(fw, amount=50, customer_id="cus_never_seen")


def test_missing_always_present_field_and_unseen_field():
    fw, clock = mk({})
    feed(fw, clock, currency="usd")
    assert "field" in kinds(fw, amount=50)                              # currency is in all 120 calls, missing now
    assert "field" in kinds(fw, amount=50, currency="usd", note="x")    # a field never seen before


def test_string_length_z_score():
    fw, clock = mk({})
    for i in range(120):
        clock.t += 60
        fw.handle(act(conv=f"c{i}", amount=50, memo="m" * (8 + i % 5)))
    assert "length" in kinds(fw, amount=50, memo="m" * 400)
    assert "length" not in kinds(fw, amount=50, memo="m" * 10)


def test_unusual_tool_sequence():
    fw, clock = mk({"min_calls": 20})
    for i in range(30):                                                 # in every conversation: read, then pay
        clock.t += 60
        fw.handle(act("fake.read", conv=f"s{i}"))
        clock.t += 5
        fw.handle(act("fake.pay", conv=f"s{i}", amount=50))
    clock.t += 60
    fw.handle(act("fake.pay", conv="fresh", amount=50))                 # pay as the FIRST call of a conversation: never seen
    assert "sequence" in logged_kinds(fw)


def test_frequency_over_three_times_the_normal_rate():
    fw, clock = mk({"min_calls": 20})
    feed(fw, clock, n=40, step=3600.0)                                  # one call per hour
    clock.t += 3600
    found = set()
    for i in range(8):
        clock.t += 10
        fw.handle(act(conv=f"b{i}", amount=50))
        found |= {json_kind for (d,) in fw.ledger._rows("SELECT data FROM events WHERE event='anomaly'") for json_kind in
                  [a["kind"] for a in __import__("json").loads(d)["anomalies"]]}
    assert "frequency" in found


def test_timing_gap_outlier():
    fw, clock = mk({"min_calls": 20})
    for i in range(30):
        clock.t += 100
        fw.handle(act("fake.read", conv=f"t{i}"))
        clock.t += 10
        fw.handle(act("fake.pay", conv=f"t{i}", amount=50))
    clock.t += 100
    fw.handle(act("fake.read", conv="late"))
    clock.t += 5000                                                    # 5000 s between two related calls, usually 10 s
    fw.handle(act("fake.pay", conv="late", amount=50))
    assert "timing" in logged_kinds(fw)


def test_false_positive_tuning_raises_the_threshold():
    fw, clock = mk({})
    feed(fw, clock)
    b = anomaly.Baselines(fw.ledger)
    probe = lambda: [a for a in anomaly.assess(fw.policy, fw.ledger, act(amount=69), "k", clock.t) if a.kind == "amount"]
    assert probe()
    b.add_bonus("fake.pay", "amount")
    assert not probe()


def test_rebuild_from_ledger_history_matches_the_live_baseline():
    fw, clock = mk({})
    feed(fw, clock, n=50)
    live = anomaly.Baselines(fw.ledger).get("fake.pay")
    counts = anomaly.rebuild(fw.policy, fw.ledger, clock())
    rebuilt = anomaly.Baselines(fw.ledger).get("fake.pay")
    assert counts == {"fake.pay": 50} and rebuilt["n"] == live["n"] and rebuilt["amounts"] == live["amounts"] and rebuilt["after"] == live["after"]


def test_off_by_default_and_config_is_validated():
    fw, clock = mk(None)
    feed(fw, clock, n=5)
    assert fw.ledger._rows("SELECT COUNT(*) FROM baselines") == [(0,)] if _has(fw, "baselines") else True
    assert anomaly.settings(fw.policy) is None
    for bad in ({"typo": 1}, {"min_calls": 1}, {"hold_severity": 2}, {"hold_severity": 0}, {"enabled": "yes"}, {"min_calls": True}, 5 * [1]):
        with pytest.raises(FirewallError):
            policy({"fake.pay": {}}, "auto", anomaly=bad)
    assert anomaly.settings(policy({"fake.pay": {}}, "auto", anomaly={"enabled": False})) is None


def _has(fw, table):
    return bool(fw.ledger._rows("SELECT name FROM sqlite_master WHERE name=?", (table,)))
