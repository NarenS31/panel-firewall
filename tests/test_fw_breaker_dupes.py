"""Per-order duplicate guard and the circuit breaker."""
import pytest

from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from panel_firewall.firewall.pin import ApprovalGate, PinStore
from panel_firewall.firewall.policy import LedgerState, evaluate, parse_policy
from panel_firewall.firewall.types import Action, FirewallError
from tests.fw_helpers import POLICY_SHA, FakeConnector, act, make_fw, signer

DAY = 86400.0


class Clock:
    def __init__(self, t=1_000_000.0): self.t = t
    def __call__(self): return self.t
    def advance(self, s): self.t += s


REFUND = {"fake.pay": {"amount_field": "amount", "duplicate_guard": {"field": "order_id", "within_seconds": 7 * DAY}}, "fake.read": {"risk": "read"}}


# ------------------------------------------------------------------------------------------------ duplicate guard
def test_second_refund_on_the_same_order_needs_a_human_within_the_window():
    clk = Clock(); fw = make_fw(REFUND, clock=clk)
    assert fw.handle(act(amount=10, order_id="A1")).status == "executed"
    clk.advance(3 * DAY)
    o = fw.handle(act(amount=15, order_id="A1"))                   # different amount, so not an idempotent replay
    assert o.status == "needs_consent" and "already had a fake.pay 3.0 days ago" in o.verdict.reasons[0]
    assert len(fw.connectors[0].calls) == 1


def test_other_orders_and_late_repeats_are_not_affected():
    clk = Clock(); fw = make_fw(REFUND, clock=clk)
    fw.handle(act(amount=10, order_id="A1"))
    assert fw.handle(act(amount=10, order_id="B2")).status == "executed"          # another order
    clk.advance(8 * DAY)
    assert fw.handle(act(amount=11, order_id="A1")).status == "executed"          # outside the 7-day window


def test_a_human_approval_lets_the_second_refund_through_and_it_is_counted_for_the_third():
    clk = Clock(); fw = make_fw(REFUND, clock=clk)
    fw.handle(act(amount=10, order_id="A1"))
    o = fw.handle(act(amount=15, order_id="A1"))
    ok, _ = fw.ledger.approve(o.approval_id, "alice")
    assert ok and fw.handle(act(amount=15, order_id="A1")).status == "executed"
    assert fw.handle(act(amount=20, order_id="A1")).status == "needs_consent"      # a third one asks again


def test_missing_order_id_blocks_and_number_ids_work():
    fw = make_fw(REFUND)
    o = fw.handle(act(amount=10))
    assert o.status == "blocked" and "missing 'order_id'" in o.verdict.reasons[0]
    fw2 = make_fw(REFUND)
    fw2.handle(act(amount=10, order_id=1042))
    assert fw2.handle(act(amount=12, order_id=1042)).status == "needs_consent"


def test_the_guard_is_per_tool_and_ignores_attempts_that_did_not_execute():
    fw = make_fw({"fake.pay": {"amount_field": "amount", "max_amount": 50, "duplicate_guard": {"field": "order_id", "within_seconds": DAY}}, "fake.read": {"risk": "read"}})
    assert fw.handle(act(amount=500, order_id="Z")).status == "blocked"            # blocked: never executed
    assert fw.handle(act(amount=40, order_id="Z")).status == "executed"            # so this is the first real refund


def test_policy_validation_rejects_a_bad_guard():
    for bad in ({"field": "order id", "within_seconds": 5}, {"field": "x", "within_seconds": 0}, {"field": "x"}, {"field": "x", "within_seconds": 5, "extra": 1}, "yes"):
        with pytest.raises(FirewallError, match="duplicate_guard"):
            parse_policy({"actions": {"t": {"duplicate_guard": bad}}}, POLICY_SHA)


def test_evaluate_is_pure_with_same_field_state():
    rule = REFUND["fake.pay"]
    a = Action("fake.pay", {"amount": 5, "order_id": "A"})
    assert evaluate(a, rule, {}, LedgerState(), 100.0).decision == "allow"
    assert evaluate(a, rule, {}, LedgerState(same_field=[50.0]), 100.0).decision == "needs_consent"


def test_shadow_mode_reports_the_would_ask_for_a_duplicate():
    clk = Clock(); fw = make_fw(REFUND, mode="shadow", clock=clk)
    fw.handle(act(amount=10, order_id="A1"))
    o = fw.handle(act(amount=11, order_id="A1"))
    assert o.status == "executed" and o.shadow["would"] == "ask"


# ------------------------------------------------------------------------------------------------ circuit breaker
def breaker_fw(clk=None, **cb):
    acts = {"fake.pay": {"max_amount": 100}, "fake.read": {"risk": "read"}}
    led = Ledger(":memory:", clock=clk) if clk else Ledger(":memory:")
    pol = parse_policy({"version": "t", "mode": "auto", "actions": acts, "circuit_breaker": cb}, POLICY_SHA)
    return Firewall(pol, led, signer(), [FakeConnector()], clock=clk or __import__("time").time)


def test_three_blocks_in_a_minute_freeze_writes_but_not_reads():
    clk = Clock(); fw = breaker_fw(clk)
    for i in range(3):
        assert fw.handle(act(amount=500 + i)).status == "blocked"
        clk.advance(5)
    assert fw.frozen() is not None
    o = fw.handle(act(amount=10))
    assert o.status == "blocked" and "circuit breaker" in o.verdict.reasons[0]
    assert fw.handle(act("fake.read")).status == "executed"                          # reads keep working
    assert len(fw.connectors[0].calls) == 1                                          # only the read ran


def test_the_freeze_writes_a_signed_receipt_and_does_not_trip_itself():
    clk = Clock(); fw = breaker_fw(clk)
    for i in range(3):
        fw.handle(act(amount=500 + i)); clk.advance(1)
    rec = [r for r in fw.ledger.receipts() if "outcome=frozen" in r["reasons"]]
    assert len(rec) == 1 and rec[0]["verdict"] == "BLOCKED" and "circuit breaker tripped: 3 blocked actions" in rec[0]["reasons"][0]
    for _ in range(5):
        fw.handle(act(amount=1))                                                     # blocked by the freeze: must not create more freezes
    assert len([r for r in fw.ledger.receipts() if "outcome=frozen" in r["reasons"]]) == 1
    assert sum(1 for e in fw.ledger.events(limit=10**6) if e["event"] == "freeze") == 1


def test_blocks_spread_over_more_than_the_window_do_not_trip():
    clk = Clock(); fw = breaker_fw(clk, blocks=3, per_seconds=60)
    for i in range(6):
        fw.handle(act(amount=500 + i)); clk.advance(40)                               # at most 2 inside any 60 s
    assert fw.frozen() is None and fw.handle(act(amount=10)).status == "executed"


def test_custom_limits_and_off_by_default():
    clk = Clock(); fw = breaker_fw(clk, blocks=2, per_seconds=10)
    fw.handle(act(amount=500)); fw.handle(act(amount=501))
    assert fw.frozen() is not None
    plain = make_fw(clock=Clock())                                                     # no circuit_breaker key: never freezes
    for i in range(10): plain.handle(act(amount=500 + i))
    assert plain.frozen() is None and plain.handle(act(amount=10)).status == "executed"
    clk2 = Clock(); off = breaker_fw(clk2, enabled=False)
    for i in range(5): off.handle(act(amount=500 + i))
    assert off.frozen() is None


def test_a_human_denial_is_not_a_trip():
    clk = Clock()
    acts = {"fake.pay": {"consent_over_amount": 5}, "fake.read": {"risk": "read"}}
    pol = parse_policy({"version": "t", "mode": "auto", "actions": acts, "circuit_breaker": {"blocks": 2, "per_seconds": 60}}, POLICY_SHA)
    fw = Firewall(pol, Ledger(":memory:", clock=clk), signer(), [FakeConnector()], clock=clk)
    for amt in (10, 11, 12):
        o = fw.handle(act(amount=amt)); fw.ledger.approve(o.approval_id, "bob", deny=True); fw.handle(act(amount=amt))
    assert fw.frozen() is None


def test_shadow_mode_never_freezes():
    clk = Clock()
    acts = {"fake.pay": {"max_amount": 100}, "fake.read": {"risk": "read"}}
    pol = parse_policy({"version": "t", "mode": "shadow", "actions": acts, "circuit_breaker": {}}, POLICY_SHA)
    fw = Firewall(pol, Ledger(":memory:", clock=clk), signer(), [FakeConnector()], clock=clk)
    for i in range(6): assert fw.handle(act(amount=500 + i)).status == "executed"
    assert fw.frozen() is None


@pytest.fixture
def pinned(tmp_path):
    store = PinStore(str(tmp_path / "pin.json")); store.set_pin("correct-horse", None)
    return store


def test_unfreeze_needs_the_pin_token_bound_to_this_freeze_and_works_once(pinned):
    clk = Clock(); fw = breaker_fw(clk)
    for i in range(3): fw.handle(act(amount=500 + i))
    ApprovalGate(fw.ledger, pinned)
    assert fw.unfreeze("eve")[0] is False and fw.frozen() is not None                  # no token
    fs = fw.ledger.freeze_state(); ref = f"freeze-{fs['seq']}"
    assert fw.unfreeze("eve", pinned.mint("other", "other"))[0] is False                # token for something else
    pinned.verify("correct-horse"); tok = pinned.mint(ref, ref)
    ok, msg = fw.unfreeze("alice", tok)
    assert ok and fw.frozen() is None
    assert fw.handle(act(amount=10)).status == "executed"
    assert any("outcome=unfrozen" in r["reasons"] for r in fw.ledger.receipts())
    assert fw.unfreeze("alice", tok) == (False, "writes are not frozen")


def test_a_used_token_cannot_unfreeze_the_next_freeze(pinned):
    clk = Clock(); fw = breaker_fw(clk); ApprovalGate(fw.ledger, pinned)
    for i in range(3): fw.handle(act(amount=500 + i))
    ref = f"freeze-{fw.ledger.freeze_state()['seq']}"; pinned.verify("correct-horse"); tok = pinned.mint(ref, ref)
    assert fw.unfreeze("a", tok)[0]
    clk.advance(120)
    for i in range(3): fw.handle(act(amount=600 + i))
    assert fw.frozen() is not None
    assert fw.unfreeze("a", tok)[0] is False and fw.frozen() is not None


def test_a_wrong_pin_never_mints_a_token(pinned):
    from panel_firewall.firewall.pin import PinError
    with pytest.raises(PinError):
        pinned.verify("nope-nope")
