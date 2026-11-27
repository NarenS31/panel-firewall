"""learned_patterns: observe -> extract pattern -> a human marks it -> rule suggestion / threshold tuning. And the cloud threat feed."""
import pytest

from panel_firewall.firewall import anomaly, learn
from panel_firewall.firewall.cli import main
from panel_firewall.firewall.cloud import THREAT_FEED_EVERY, CloudError, CloudSync
from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from tests.fw_helpers import FakeConnector, act, policy, signer
from tests.test_fw_anomaly import Clock, feed, mk

NOW = 1_700_000_000.0


def test_an_anomaly_creates_an_unconfirmed_local_pattern_and_repeats_increase_its_count():
    fw, clock = mk({})
    feed(fw, clock)
    for i in range(3):
        clock.t += 60
        fw.handle(act(conv=f"x{i}", amount=300 + i))
    ps = learn.patterns(fw.ledger, status="unconfirmed")
    amt = [p for p in ps if p["pattern_type"] == "amount_outlier"]
    assert len(amt) == 1 and amt[0]["count"] == 3 and amt[0]["source"] == "local" and amt[0]["tool"] == "fake.pay" and amt[0]["category"] == "payment"
    assert amt[0]["rule"] == "anomaly:amount" and amt[0]["field"] == "amount" and amt[0]["status"] == "unconfirmed"


def test_a_telemetry_block_records_tool_field_and_threshold_locally():
    pol = policy({"fake.pay": {"max_amount": 100, "entity_velocity": {"field": "customer_id", "max_actions": 1, "per_seconds": 3600}}}, "auto", telemetry=True)
    fw = Firewall(pol, Ledger(":memory:"), signer(), [FakeConnector()])
    fw.handle(act(amount=500, customer_id="a"))
    ps = learn.patterns(fw.ledger)
    assert len(ps) == 1
    p = ps[0]
    assert (p["pattern_type"], p["tool"], p["rule"], p["field"], p["threshold"], p["source"]) == ("cap_split", "fake.pay", "max_amount", "amount", 100.0, "local")
    # the anonymized upload row still carries no tool name or field
    cols = {r[1] for r in fw.ledger._rows("PRAGMA table_info(exploit_signatures)")}
    assert "tool" not in cols and "field" not in cols


def test_telemetry_off_records_no_exploit_pattern():
    pol = policy({"fake.pay": {"max_amount": 100}}, "auto")
    fw = Firewall(pol, Ledger(":memory:"), signer(), [FakeConnector()])
    fw.handle(act(amount=500))
    assert learn.patterns(fw.ledger) == []


def test_mark_threat_and_false_positive_and_validation():
    fw, clock = mk({})
    feed(fw, clock)
    fw.handle(act(conv="x", amount=300))
    pid = learn.patterns(fw.ledger)[0]["id"]
    assert "real threat" in learn.mark(fw.ledger, pid, "threat", "alice")
    p = learn.patterns(fw.ledger)[0]
    assert p["status"] == "threat" and p["decided_by"] == "alice" and p["decided_at"]
    assert learn.patterns(fw.ledger, status="unconfirmed") == []
    with pytest.raises(ValueError):
        learn.mark(fw.ledger, pid, "maybe", "alice")
    with pytest.raises(ValueError):
        learn.mark(fw.ledger, pid, "threat", "  ")
    with pytest.raises(ValueError):
        learn.mark(fw.ledger, 999, "threat", "alice")


def test_false_positive_raises_the_anomaly_threshold_so_it_is_not_flagged_again():
    fw, clock = mk({})
    feed(fw, clock)
    clock.t += 60
    fw.handle(act(conv="x", amount=69))
    pid = [p for p in learn.patterns(fw.ledger) if p["pattern_type"] == "amount_outlier"][0]["id"]
    n_before = fw.ledger._rows("SELECT COUNT(*) FROM events WHERE event='anomaly'")[0][0]
    assert n_before == 1
    msg = learn.mark(fw.ledger, pid, "false_positive", "alice")
    assert "looser" in msg and anomaly.Baselines(fw.ledger).bonus("fake.pay", "amount") == 0.5
    clock.t += 60
    fw.handle(act(conv="y", amount=69))
    assert fw.ledger._rows("SELECT COUNT(*) FROM events WHERE event='anomaly'")[0][0] == n_before          # not flagged again


def test_false_positive_on_a_policy_rule_pattern_never_loosens_the_policy():
    pol = policy({"fake.pay": {"max_amount": 100}}, "auto", telemetry=True)
    fw = Firewall(pol, Ledger(":memory:"), signer(), [FakeConnector()])
    fw.handle(act(amount=500))
    pid = learn.patterns(fw.ledger)[0]["id"]
    assert "never loosened" in learn.mark(fw.ledger, pid, "false_positive", "alice")
    assert fw.handle(act(conv="c2", amount=500)).status == "blocked"                                          # still enforced


def test_hints_show_how_people_decided_earlier_holds():
    pol = policy({"fake.pay": {"consent_over_amount": 10}}, "auto")
    fw = Firewall(pol, Ledger(":memory:"), signer(), [FakeConnector()])
    fw.handle(act(conv="a", amount=50))
    fw.handle(act(conv="b", amount=60))
    for ap in fw.ledger.pending():
        fw.ledger.approve(ap["approval_id"], "bob", deny=(ap["args"]["amount"] == 60), reason="no")
    assert learn.hints(fw.ledger, "fake.pay") == {"approved": 1, "denied": 1}
    assert learn.hints(fw.ledger, None) == {"approved": 0, "denied": 0}


# ------------------------------------------------------------------------------------------------ the cloud feed
GOOD = {"pattern_type": "cap_split", "tool_category": "payment", "rule_triggered": "max_total_amount", "amount_ratio": 2.5, "seen": 120, "deployments": 9}


def test_merge_feed_stores_cloud_patterns_unconfirmed_without_a_tool_name():
    led = Ledger(":memory:")
    assert learn.merge_feed(led, {"patterns": [GOOD]}, NOW) == 1
    p = learn.patterns(led)[0]
    assert (p["source"], p["status"], p["tool"], p["category"], p["count"], p["deployments"], p["threshold"]) == ("cloud", "unconfirmed", None, "payment", 120, 9, 2.5)
    learn.merge_feed(led, {"patterns": [{**GOOD, "seen": 150}]}, NOW + 5)
    learn.merge_feed(led, {"patterns": [{**GOOD, "seen": 100}]}, NOW + 6)                    # the feed's totals are absolute, never summed
    ps = learn.patterns(led)
    assert len(ps) == 1 and ps[0]["count"] == 150


def test_merge_feed_drops_anything_outside_the_closed_vocabulary():
    led = Ledger(":memory:")
    bad = [{**GOOD, "pattern_type": "rm_rf"}, {**GOOD, "tool_category": "x'; DROP TABLE events;--"}, {**GOOD, "rule_triggered": "a; DROP TABLE"},
           {**GOOD, "seen": -3}, {**GOOD, "seen": "many"}, {**GOOD, "seen": True}, {**GOOD, "amount_ratio": float("nan")}, "str", None, 5, {}]
    assert learn.merge_feed(led, {"patterns": bad}) == 0 or all(p["rule"] == "max_total_amount" for p in learn.patterns(led))
    assert all(p["pattern_type"] in learn.ALL_TYPES for p in learn.patterns(led))
    for junk in (None, [], "x", {"patterns": "no"}, {"patterns": {"a": 1}}, {}):
        assert learn.merge_feed(led, junk) == 0
    assert led._rows("SELECT COUNT(*) FROM events")[0][0] == 0                               # the feed never writes ledger events
    assert learn.merge_feed(led, {"patterns": [GOOD] * 2000}) == 500                          # bounded


class FeedClient:
    def __init__(self, payload=None, fail=False):
        self.payload, self.fail, self.calls = payload or {"patterns": [GOOD]}, fail, 0

    def threat_feed(self):
        self.calls += 1
        if self.fail:
            raise CloudError("cloud error 404: ")
        return self.payload


def sync_for(fw, client, clock):
    s = CloudSync.__new__(CloudSync)
    s.client, s.fw, s.clock, s._last_feed = client, fw, clock, -1e18
    return s


def fw_with(telemetry):
    return Firewall(policy({"fake.pay": {"max_amount": 100}}, "auto", **({"telemetry": True} if telemetry else {})), Ledger(":memory:"), signer(), [FakeConnector()])


def test_threat_feed_is_pulled_only_with_telemetry_on_and_throttled():
    t = [NOW]
    fw, c = fw_with(True), FeedClient()
    s = sync_for(fw, c, lambda: t[0])
    assert s.pull_threat_feed() == 1 and c.calls == 1
    t[0] += THREAT_FEED_EVERY - 1
    assert s.pull_threat_feed() == 0 and c.calls == 1
    t[0] += 2
    assert s.pull_threat_feed() == 1 and c.calls == 2
    off, c2 = fw_with(False), FeedClient()
    assert sync_for(off, c2, lambda: NOW).pull_threat_feed() == 0 and c2.calls == 0


def test_a_cloud_without_the_endpoint_just_merges_nothing():
    fw = fw_with(True)
    assert sync_for(fw, FeedClient(fail=True), lambda: NOW).pull_threat_feed() == 0
    assert learn.patterns(fw.ledger) == []


def test_cloud_patterns_never_change_a_verdict():
    fw = fw_with(True)
    before = [fw.handle(act(conv=f"a{i}", amount=a)).status for i, a in enumerate((10, 90, 500))]
    sync_for(fw, FeedClient({"patterns": [GOOD, {**GOOD, "pattern_type": "forbidden_tool", "rule_triggered": "allowed"}]}), lambda: NOW).pull_threat_feed()
    assert len(learn.patterns(fw.ledger, source="cloud")) == 2
    after = [fw.handle(act(conv=f"b{i}", amount=a)).status for i, a in enumerate((10, 90, 500))]
    assert before == after == ["executed", "executed", "blocked"]


def test_tick_calls_the_feed_after_the_telemetry_upload():
    import inspect
    from panel_firewall.firewall import cloud
    src = inspect.getsource(cloud.CloudSync.tick)
    assert src.index("upload_telemetry") < src.index("pull_threat_feed")


def test_cli_learn_mark(tmp_path, capsys):
    db = str(tmp_path / "l.sqlite")
    led = Ledger(db)
    learn.merge_feed(led, {"patterns": [GOOD]})
    assert main(["learn", "--ledger", db, "--list"]) == 0
    out = capsys.readouterr().out
    assert "(cloud)" in out and "cap_split" in out and "any payment tool" in out
    assert main(["learn", "--ledger", db, "--mark", "1", "--as", "threat", "--who", "alice"]) == 0
    assert "real threat" in capsys.readouterr().out
    assert Ledger(db)._rows("SELECT status, decided_by FROM learned_patterns") == [("threat", "alice")]
    assert main(["learn", "--ledger", db]) == 0 and "No unconfirmed patterns." in capsys.readouterr().out


def test_cli_baseline_rebuild(tmp_path, capsys):
    db = str(tmp_path / "l.sqlite")
    pol = policy({"fake.pay": {}}, "auto")
    clock = Clock()
    fw = Firewall(pol, Ledger(db, clock=clock), signer(), [FakeConnector()], clock=clock)
    for i in range(12):
        clock.t += 60
        fw.handle(act(conv=f"c{i}", amount=10 + i))
    import yaml
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({"version": "t", "mode": "auto", "actions": {"fake.pay": {}}}))
    assert main(["baseline", "--policy", str(p), "--ledger", db, "--rebuild"]) == 0
    out = capsys.readouterr().out
    assert "fake.pay (12 calls)" in out and "p99 21" in out
