"""`usepanel suggest`: templated rule suggestions from observed traffic. Panel never activates one."""
import json
import time

import yaml

from panel_firewall.firewall import suggest
from panel_firewall.firewall.cli import main
from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from panel_firewall.firewall.policy import load_policy
from tests.fw_helpers import FakeConnector, act, policy, signer
from panel_firewall.firewall.types import ActionSchema, Result

DAY0 = (int(time.time()) // 86400 - 2) * 86400 + 3600      # an aligned UTC day start, two days ago


class Conn(FakeConnector):
    def describe_actions(self):
        return super().describe_actions() + [ActionSchema("db.query", "q", {"sql": {"type": "string"}}, ("sql",), "write")]

    def execute(self, action, mode):
        if action.tool == "db.query":
            return Result(True, "r", {"rows": 1})
        return super().execute(action, mode)


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def shadow_traffic(path=":memory:", acts=None, n=150, per_hour=10, customers=75, mode="shadow"):
    clock = Clock(DAY0)
    pol = policy(acts or {"fake.pay": {"risk": "write"}, "fake.read": {"risk": "read"}, "db.query": {"risk": "write"}}, mode)
    fw = Firewall(pol, Ledger(path, clock=clock), signer(), [Conn()], clock=clock)
    amounts = [20 + (i * 7) % 123 for i in range(n)]
    amounts[5] = 142.5                                      # the observed max
    for i in range(n):
        clock.t = DAY0 + (i // per_hour) * 3600 + (i % per_hour) * 60
        assert fw.handle(act("fake.pay", conv=f"c{i}", amount=amounts[i], customer_id=f"cus_{i % customers}")).status == "executed"
    return fw, clock


def test_nice_up_rounds_to_two_significant_figures():
    assert suggest.nice_up(149.625) == 150 and suggest.nice_up(142.5) == 150 and suggest.nice_up(7.3) == 7.3 and suggest.nice_up(1234) == 1300
    assert suggest.nice_up(0) == 0 and suggest.nice_up(0.0123) == 0.013


def test_suggests_amount_rate_and_entity_rules_from_the_observed_distribution():
    fw, _c = shadow_traffic()
    res = suggest.analyze(fw.ledger, fw.policy, DAY0 - 1, from_shadow=True)
    r = res["tools"]["fake.pay"]["rules"]
    assert res["total"] == 150
    assert r["max_amount"] == 150                                      # observed max 142.5 -> x1.05 = 149.6 -> 150
    assert r["rate_limit"] == {"max": 12, "per_seconds": 3600}         # busiest hour was 10
    assert r["entity_velocity"] == {"field": "customer_id", "max_actions": 2, "per_seconds": 86400}
    assert "observed max was 142.5" in res["tools"]["fake.pay"]["notes"]["max_amount"]
    text = suggest.format_suggestions(res, "7d")
    assert text.startswith("Suggested rules based on 7d of shadow mode traffic (150 tool calls):")
    assert "max_amount: 150" in text and "per_seconds: 3600" in text and "field: customer_id" in text


def test_rules_the_policy_already_has_are_not_suggested_again():
    fw, _c = shadow_traffic(acts={"fake.pay": {"risk": "write", "max_amount": 500, "rate_limit": {"max": 99, "per_seconds": 60}}, "fake.read": {"risk": "read"},
                                  "db.query": {"risk": "write"}})
    r = suggest.analyze(fw.ledger, fw.policy, DAY0 - 1)["tools"]["fake.pay"]["rules"]
    assert "max_amount" not in r and "rate_limit" not in r and "entity_velocity" in r


def test_a_tool_with_too_few_calls_gets_no_suggestion():
    fw, _c = shadow_traffic(n=40)
    res = suggest.analyze(fw.ledger, fw.policy, DAY0 - 1)
    assert res["tools"] == {} and res["skipped"] == {"fake.pay": 40}
    assert "only 40 calls" in suggest.format_suggestions(res)
    assert suggest.analyze(fw.ledger, fw.policy, DAY0 - 1, min_calls=30)["tools"]


def test_sql_kinds_never_seen_in_normal_traffic_are_suggested():
    fw, c = shadow_traffic(n=10)
    for i in range(120):
        c.t += 5
        fw.handle(act("db.query", conv=f"q{i}", sql=f"SELECT * FROM orders WHERE id = {i}" if i % 10 else f"UPDATE orders SET a=1 WHERE id={i}"))
    r = suggest.analyze(fw.ledger, fw.policy, DAY0 - 1)["tools"]["db.query"]
    assert r["rules"]["consent_sql_kinds"] == ["delete", "drop", "truncate", "alter"]
    assert r["notes"]["consent_sql_kinds"] == "never observed in normal traffic"
    assert "consent_sql_kinds: [delete, drop, truncate, alter]" in suggest.format_suggestions(suggest.analyze(fw.ledger, fw.policy, DAY0 - 1))


def test_a_sql_kind_that_does_appear_is_not_suggested():
    fw, c = shadow_traffic(n=10)
    for i in range(120):
        c.t += 5
        fw.handle(act("db.query", conv=f"q{i}", sql="DELETE FROM carts WHERE id=1" if i % 2 else "SELECT 1"))
    assert "delete" not in suggest.analyze(fw.ledger, fw.policy, DAY0 - 1)["tools"]["db.query"]["rules"]["consent_sql_kinds"]


def test_from_shadow_only_counts_calls_that_ran_in_shadow_mode():
    fw, _c = shadow_traffic(mode="auto")
    assert suggest.analyze(fw.ledger, fw.policy, DAY0 - 1, from_shadow=True)["total"] == 0
    assert suggest.analyze(fw.ledger, fw.policy, DAY0 - 1)["total"] == 150


def test_merge_never_overwrites_and_the_proposal_never_touches_the_live_policy(tmp_path):
    live = tmp_path / "policy.yaml"
    raw = {"version": "t", "mode": "shadow", "actions": {"fake.pay": {"risk": "write", "max_amount": 999}}}
    live.write_text(yaml.safe_dump(raw))
    before = live.read_bytes()
    merged = suggest.merge(raw, {"fake.pay": {"max_amount": 150, "rate_limit": {"max": 12, "per_seconds": 3600}}})
    assert merged["actions"]["fake.pay"]["max_amount"] == 999 and merged["actions"]["fake.pay"]["rate_limit"]["max"] == 12
    assert raw["actions"]["fake.pay"].get("rate_limit") is None                      # the input is not mutated
    out = suggest.write_proposal(str(live), raw, {"fake.pay": {"rate_limit": {"max": 12, "per_seconds": 3600}}})
    assert out.name == "policy.suggested.yaml" and live.read_bytes() == before
    assert load_policy(out).rule_for("fake.pay")["rate_limit"]["max"] == 12            # it is a valid policy
    import pytest
    from panel_firewall.firewall.types import FirewallError
    with pytest.raises(FirewallError):
        suggest.write_proposal(str(live), raw, {}, str(live))


def test_review_flows():
    res = {"tools": {"a": {"rules": {"max_amount": 5, "rate_limit": {"max": 2, "per_seconds": 60}}}, "b": {"rules": {"max_amount": 9}}}}
    assert suggest.review(res, lambda q: "skip") == {}
    assert suggest.review(res, lambda q: "accept all") == {"a": {"max_amount": 5, "rate_limit": {"max": 2, "per_seconds": 60}}, "b": {"max_amount": 9}}
    answers = iter(["review each", "y", "n", "yes"])
    assert suggest.review(res, lambda q: next(answers)) == {"a": {"max_amount": 5}, "b": {"max_amount": 9}}


def test_cli_end_to_end_writes_a_proposal_and_leaves_the_policy_alone(tmp_path, capsys):
    db = str(tmp_path / "l.sqlite")
    fw, _c = shadow_traffic(db)
    live = tmp_path / "policy.yaml"
    live.write_text(yaml.safe_dump({"version": "t", "mode": "shadow", "actions": {"fake.pay": {"risk": "write"}, "fake.read": {"risk": "read"}, "db.query": {"risk": "write"}}}))
    before = live.read_bytes()
    assert main(["suggest", "--policy", str(live), "--ledger", db, "--since", "7d", "--from-shadow", "--accept", "skip"]) == 0
    out = capsys.readouterr().out
    assert "Suggested rules based on 7d of shadow mode traffic (150 tool calls)" in out and not (tmp_path / "policy.suggested.yaml").exists()
    assert main(["suggest", "--policy", str(live), "--ledger", db, "--from-shadow", "--accept", "all"]) == 0
    assert "does NOT use it yet" in capsys.readouterr().out
    prop = yaml.safe_load((tmp_path / "policy.suggested.yaml").read_text())
    assert prop["actions"]["fake.pay"]["max_amount"] == 150 and live.read_bytes() == before
    # without a terminal and without --accept it only prints
    (tmp_path / "policy.suggested.yaml").unlink()
    assert main(["suggest", "--policy", str(live), "--ledger", db, "--from-shadow"]) == 0
    assert "Nothing was changed" in capsys.readouterr().out and not (tmp_path / "policy.suggested.yaml").exists()


def test_confirmed_threat_and_cloud_patterns_become_suggestions_but_false_positives_do_not():
    from panel_firewall.firewall import anomaly, learn
    fw, _c = shadow_traffic(acts={"fake.pay": {"risk": "write", "max_amount": 500, "rate_limit": {"max": 99, "per_seconds": 60}, "entity_velocity": {"field": "customer_id", "max_actions": 9, "per_seconds": 5}},
                                  "fake.read": {"risk": "read"}, "db.query": {"risk": "write"}}, mode="shadow")
    anomaly.rebuild(fw.policy, fw.ledger, DAY0)
    pid = learn._upsert(fw.ledger, source="local", pattern_type="amount_outlier", tool="fake.pay", category="payment", rule="anomaly:amount", field="amount", now=DAY0)
    assert "consent_over_amount" not in suggest.analyze(fw.ledger, fw.policy, DAY0 - 1)["tools"].get("fake.pay", {"rules": {}})["rules"]    # unconfirmed local: ignored
    learn.mark(fw.ledger, pid, "threat", "alice")
    ent = suggest.analyze(fw.ledger, fw.policy, DAY0 - 1)["tools"]["fake.pay"]
    assert ent["rules"]["consent_over_amount"] == 150 and "confirmed as a threat" in ent["notes"]["consent_over_amount"]
    learn.mark(fw.ledger, pid, "false_positive", "alice")
    assert "consent_over_amount" not in suggest.analyze(fw.ledger, fw.policy, DAY0 - 1)["tools"].get("fake.pay", {"rules": {}})["rules"]
    learn.merge_feed(fw.ledger, {"patterns": [{"pattern_type": "velocity_burst", "tool_category": "payment", "rule_triggered": "rate_limit", "seen": 40, "deployments": 7}]})
    fw2, _ = shadow_traffic(acts={"fake.pay": {"risk": "write"}, "fake.read": {"risk": "read"}, "db.query": {"risk": "write"}})
    anomaly.rebuild(fw2.policy, fw2.ledger, DAY0)
    learn.merge_feed(fw2.ledger, {"patterns": [{"pattern_type": "velocity_burst", "tool_category": "payment", "rule_triggered": "rate_limit", "seen": 40, "deployments": 7}]})
    text = suggest.format_suggestions(suggest.analyze(fw2.ledger, fw2.policy, DAY0 - 1))
    assert "reported by the cloud threat feed (unconfirmed)" in text
