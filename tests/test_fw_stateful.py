"""Cross-session stateful rules: rate_limit / max_total_amount across conversations, entity_velocity, max_total_outflow."""
from panel_firewall.firewall.connector import Connector
from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from panel_firewall.firewall.types import ActionSchema, Result
from tests.fw_helpers import act, policy, signer


class MoneyConnector(Connector):
    name = "money"
    TOOLS = ("refunds.create", "credits.issue", "balance.withdraw", "notes.add")

    def __init__(self):
        self.calls = []

    def describe_actions(self):
        return [ActionSchema(t, t, {"amount": {"type": "number"}}, (), "write") for t in self.TOOLS]

    def execute(self, action, mode):
        self.calls.append(action)
        return Result(True, f"id-{len(self.calls)}", {})


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def fw_for(actions, **top):
    clock = Clock()
    fw = Firewall(policy(actions, "auto", **top), Ledger(":memory:", clock=clock), signer(), [MoneyConnector()], clock=clock)
    return fw, clock


def run(fw, tool, conv, **args):
    return fw.handle(act(tool, conv, **args))


# ------------------------------------------------------------------ cross-session rate limit / total amount
def test_rate_limit_counts_across_conversations_by_default():
    fw, _ = fw_for({"refunds.create": {"rate_limit": {"max": 5, "per_seconds": 3600}}})
    for i in range(5):
        assert run(fw, "refunds.create", f"conv-{i % 3}", ref=i).status == "executed"     # 3 different conversation_ids
    o = run(fw, "refunds.create", "conv-new", ref=99)
    assert o.status == "blocked" and "rate limit" in o.verdict.reasons[0]
    assert len(fw.connectors[0].calls) == 5


def test_rate_limit_cross_session_false_is_per_conversation():
    fw, _ = fw_for({"refunds.create": {"rate_limit": {"max": 2, "per_seconds": 3600, "cross_session": False}}})
    assert run(fw, "refunds.create", "a", ref=1).status == "executed"
    assert run(fw, "refunds.create", "a", ref=2).status == "executed"
    assert run(fw, "refunds.create", "a", ref=3).status == "blocked"
    assert run(fw, "refunds.create", "b", ref=4).status == "executed"      # a fresh conversation has its own window


def test_max_total_amount_counts_across_conversations_and_can_be_scoped():
    fw, _ = fw_for({"refunds.create": {"max_total_amount": {"amount": 100, "per_seconds": 3600}}})
    assert run(fw, "refunds.create", "a", amount=60).status == "executed"
    o = run(fw, "refunds.create", "b", amount=60)
    assert o.status == "blocked" and "cumulative" in o.verdict.reasons[0]
    fw2, _ = fw_for({"refunds.create": {"max_total_amount": {"amount": 100, "per_seconds": 3600, "cross_session": False}}})
    assert run(fw2, "refunds.create", "a", amount=60).status == "executed"
    assert run(fw2, "refunds.create", "b", amount=60).status == "executed"


# ------------------------------------------------------------------ entity velocity
EV = {"refunds.create": {"entity_velocity": {"field": "customer_id", "max_actions": 3, "per_seconds": 3600}}}


def test_entity_velocity_blocks_4th_refund_to_same_customer_across_sessions():
    fw, _ = fw_for(EV)
    for i in range(3):
        assert run(fw, "refunds.create", f"session-{i}", customer_id="cus_1", amount=5 + i).status == "executed"
    o = run(fw, "refunds.create", "session-9", customer_id="cus_1", amount=50)
    assert o.status == "blocked" and "entity velocity" in o.verdict.reasons[0]
    assert len(fw.connectors[0].calls) == 3


def test_entity_velocity_allows_4th_refund_to_a_different_customer():
    fw, _ = fw_for(EV)
    for i in range(3):
        run(fw, "refunds.create", f"session-{i}", customer_id="cus_1", amount=5 + i)
    assert run(fw, "refunds.create", "session-9", customer_id="cus_2", amount=50).status == "executed"


def test_entity_velocity_window_expires_and_missing_field_blocks():
    fw, clock = fw_for(EV)
    for i in range(3):
        run(fw, "refunds.create", f"s{i}", customer_id="cus_1", amount=5 + i)
    clock.t += 3601
    assert run(fw, "refunds.create", "s9", customer_id="cus_1", amount=50).status == "executed"
    o = run(fw, "refunds.create", "s9", amount=1)
    assert o.status == "blocked" and "customer_id" in o.verdict.reasons[0]


# ------------------------------------------------------------------ max_total_outflow
OUT = {"max_total_outflow": {"amount": 1000, "per_seconds": 86400, "tools": ["refunds.create", "credits.issue", "balance.withdraw"]}}
OUT_ACTIONS = {t: {} for t in MoneyConnector.TOOLS}


def test_outflow_blocks_split_across_tools():
    fw, _ = fw_for(OUT_ACTIONS, **OUT)
    assert run(fw, "refunds.create", "a", amount=400).status == "executed"
    assert run(fw, "credits.issue", "b", amount=400).status == "executed"
    o = run(fw, "balance.withdraw", "c", amount=300)               # 1100 > 1000
    assert o.status == "blocked" and "total outflow" in o.verdict.reasons[0]
    assert len(fw.connectors[0].calls) == 2


def test_outflow_allows_under_cap_and_exactly_at_cap():
    fw, _ = fw_for(OUT_ACTIONS, **OUT)
    assert run(fw, "refunds.create", "a", amount=400).status == "executed"
    assert run(fw, "credits.issue", "b", amount=400).status == "executed"
    assert run(fw, "balance.withdraw", "c", amount=200).status == "executed"     # exactly 1000


def test_outflow_only_counts_listed_tools_and_window():
    fw, clock = fw_for(OUT_ACTIONS, **OUT)
    assert run(fw, "notes.add", "a", amount=5000).status == "executed"           # not listed: neither counted nor limited
    assert run(fw, "refunds.create", "a", amount=900).status == "executed"       # the 5000 above did not count
    assert run(fw, "credits.issue", "b", amount=200).status == "blocked"
    clock.t += 86401
    assert run(fw, "credits.issue", "b", amount=200).status == "executed"        # old money left the window


def test_outflow_policy_validation():
    import pytest

    from panel_firewall.firewall.types import FirewallError
    for bad in ({"amount": 0, "per_seconds": 60, "tools": ["a"]}, {"amount": 5, "per_seconds": 60, "tools": []},
                {"amount": 5, "per_seconds": 60}, {"amount": 5, "per_seconds": 60, "tools": ["a"], "typo": 1}):
        with pytest.raises(FirewallError):
            fw_for({"a": {}}, max_total_outflow=bad)
