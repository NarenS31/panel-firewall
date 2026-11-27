"""`usepanel demo`: a zero-setup, self-contained walkthrough of the action firewall.

Everything lives in a temporary directory that is deleted afterwards: a throwaway signing key, ledger and approval PIN,
an in-memory policy and a fake support-desk connector. Nothing is read from or written to your real Panel config,
and no network, API key or model is used. The verdicts come from the real engine.
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

from panel_firewall.firewall.connector import Connector
from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from panel_firewall.firewall.pin import ApprovalGate, PinStore
from panel_firewall.firewall.policy import parse_policy
from panel_firewall.firewall.receipts import Signer, generate_key
from panel_firewall.firewall.types import Action, ActionSchema, Result

DEMO_PIN = "demo-pin-123"

POLICY = {
    "version": "demo",
    "mode": "auto",
    "circuit_breaker": {"blocks": 2, "per_seconds": 60},
    "actions": {
        "support.lookup_order": {"risk": "read", "allowed": True},
        "support.refund": {"risk": "write", "amount_field": "amount", "max_amount": 250, "consent_over_amount": 100},
        "support.delete_all_records": {"risk": "destructive", "allowed": False},
    },
}


class DemoConnector(Connector):
    """A pretend support-desk backend. It only records what 'ran'; nothing real is touched."""
    name = "demo"

    def __init__(self):
        self.ran: list[str] = []

    def describe_actions(self):
        return [
            ActionSchema("support.lookup_order", "Look up an order", {"order_id": {"type": "string"}}, ("order_id",), "read"),
            ActionSchema("support.refund", "Refund an order", {"order_id": {"type": "string"}, "amount": {"type": "number"}},
                         ("order_id", "amount"), "write", ("refund",)),
            ActionSchema("support.delete_all_records", "Delete every customer record", {}, (), "destructive"),
        ]

    def execute(self, action, mode):
        self.ran.append(action.tool)
        if action.tool == "support.refund":
            return Result(True, f"re_demo_{len(self.ran)}", {"refunded": action.args.get("amount")})
        return Result(True, "ok", {"status": "ok"})


class _Term:
    def __init__(self, color: bool, delay: float):
        self.color, self.delay = color, delay

    def c(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.color else s

    def type(self, s: str, code: str = "", delay: float | None = None) -> None:
        d = self.delay if delay is None else delay
        for ch in s:
            sys.stdout.write(self.c(code, ch) if code else ch)
            sys.stdout.flush()
            if d:
                time.sleep(d)
        sys.stdout.write("\n")
        sys.stdout.flush()

    def pause(self, s: float) -> None:
        if self.delay:
            time.sleep(s)


def _show(t: _Term, n: int, title: str, call: str) -> None:
    t.pause(0.5)
    print()
    print(t.c("1;36", f"[{n}/5] {title}"))
    t.type(f"  agent> {call}", "37", t.delay)
    t.pause(0.3)


def _verdict(t: _Term, kind: str, text: str, reasons=()) -> None:
    code, label = {"allow": ("1;32", "ALLOWED"), "block": ("1;31", "BLOCKED"), "hold": ("1;33", "HELD"), "freeze": ("1;35", "FROZEN")}[kind]
    print(f"  {t.c(code, label)}  {text}")
    for r in reasons:
        print(f"           {t.c('2', r)}")


def run_demo(color: bool | None = None, fast: bool = False) -> int:
    import logging
    logging.getLogger("panel_firewall.firewall").setLevel(logging.CRITICAL)   # the demo prints its own narration
    color = sys.stdout.isatty() if color is None else color
    t = _Term(color, 0.0 if (fast or not sys.stdout.isatty()) else 0.012)
    with tempfile.TemporaryDirectory(prefix="panel-demo-") as d:
        d = Path(d)
        signer = Signer.load(generate_key(d / "demo.key"))
        ledger = Ledger(d / "ledger.sqlite")
        gate = ApprovalGate(ledger, PinStore(d / "pin.json"))
        gate.store.set_pin(DEMO_PIN, n=2 ** 10)           # a cheap scrypt cost: this PIN protects nothing but the demo
        conn = DemoConnector()
        fw = Firewall(parse_policy(POLICY, "0" * 64), ledger, signer, [conn])

        print(t.c("1", "Panel demo") + "  a simulated support agent tries five actions. Nothing real is touched.")
        print(t.c("2", "Temporary key, ledger and PIN; all deleted when this ends. No network, no API keys."))
        print(t.c("2", "Policy: refunds over $100 need a human, over $250 are blocked, deleting records is never allowed."))

        # 1. lookup
        _show(t, 1, "Look up an order (a read)", 'support.lookup_order(order_id="1042")')
        o = fw.handle(Action("support.lookup_order", {"order_id": "1042"}, "demo"))
        _verdict(t, "allow", "read-only lookups pass; signed receipt written" if o.status == "executed" else o.status)

        # 2. small refund
        _show(t, 2, "Refund $45 (under the $100 limit)", 'support.refund(order_id="1042", amount=45)')
        o = fw.handle(Action("support.refund", {"order_id": "1042", "amount": 45}, "demo"))
        _verdict(t, "allow", f"refund ran once ({o.result.result_id}); signed receipt written" if o.status == "executed" else o.status)

        # 3. over limit
        _show(t, 3, "Refund $500 (over the $250 hard cap)", 'support.refund(order_id="1043", amount=500)')
        o = fw.handle(Action("support.refund", {"order_id": "1043", "amount": 500}, "demo"))
        _verdict(t, "block", "nothing ran; the agent is told why", o.verdict.reasons if o.status == "blocked" else [o.status])

        # 4. held, then approved
        _show(t, 4, "Refund $200 (needs a human)", 'support.refund(order_id="1044", amount=200)')
        a4 = Action("support.refund", {"order_id": "1044", "amount": 200}, "demo")
        o = fw.handle(a4)
        if o.status == "needs_consent":
            _verdict(t, "hold", f"held for approval ({o.approval_id}); the agent cannot approve its own action")
            t.pause(0.8)
            t.type("  human> usepanel approve " + o.approval_id + "   (PIN typed at the terminal)", "33", t.delay)
            ok, msg = gate.decide(o.approval_id, "demo-human", DEMO_PIN)
            t.pause(0.4)
            o = fw.handle(a4)
            _verdict(t, "allow", f"approved by a human ({msg}); the refund ran once ({o.result.result_id})" if o.status == "executed" else o.status)
        else:
            _verdict(t, "block", f"unexpected: {o.status}")

        # 5. delete_all + circuit breaker
        _show(t, 5, "Delete every customer record (destructive)", "support.delete_all_records()")
        o = fw.handle(Action("support.delete_all_records", {}, "demo"))
        _verdict(t, "block", "nothing ran; this is the second block in under a minute", o.verdict.reasons if o.status == "blocked" else [o.status])
        t.pause(0.4)
        fz = fw.frozen()
        if fz:
            _verdict(t, "freeze", "circuit breaker tripped: every non-read tool is frozen until a human runs `usepanel unfreeze`")
        t.pause(0.4)
        t.type('  agent> support.refund(order_id="1045", amount=10)   (even a small one)', "37", t.delay)
        o = fw.handle(Action("support.refund", {"order_id": "1045", "amount": 10}, "demo"))
        _verdict(t, "freeze" if o.status == "blocked" else "allow", "refused while frozen" if o.status == "blocked" else o.status)
        t.pause(0.3)
        o = fw.handle(Action("support.lookup_order", {"order_id": "1042"}, "demo"))
        _verdict(t, "allow", "reads still work" if o.status == "executed" else o.status)

        receipts = ledger.receipts()
        pub = signer.pubkey
        from panel_firewall.firewall.receipts import verify_receipt
        good = sum(1 for r in receipts if not verify_receipt(r, pub))
        print()
        print(t.c("1", "Summary"))
        print(f"  Simulated actions that ran: {len(conn.ran)} of 7 attempted ({', '.join(conn.ran)})")
        print(f"  Signed receipts written: {len(receipts)}; signatures that verify: {good}")
        print(t.c("2", "Next: `usepanel init -- <your MCP server command>` drafts a policy, then `usepanel proxy --shadow` to try it on real traffic."))
        ledger._db.close()
    return 0
