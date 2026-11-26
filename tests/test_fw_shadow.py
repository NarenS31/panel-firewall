"""Shadow mode (evaluate, log 'would have', let it run), the by-rule report, and PII scrubbing of summaries/exports."""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from panel_firewall.firewall.cli import main
from panel_firewall.firewall.policy import parse_policy
from panel_firewall.firewall.scrub import scrub, scrub_text
from panel_firewall.firewall.summary import (
    build_report,
    export_log,
    format_report,
    parse_since,
    rule_of,
)
from panel_firewall.firewall.types import FirewallError
from tests.fw_helpers import (
    FakeConnector,
    McpClient,
    act,
    make_fw,
    panel_cmd,
    policy,
    text_of,
)
from tests.test_fw_gateway import FAKE, rig, run, upstream_calls  # noqa: F401  (fixture)

ACTIONS = {"fake.pay": {"max_amount": 100, "consent_over_amount": 50}, "fake.read": {"risk": "read"}}


def shadow_fw(**kw):
    conn = FakeConnector()
    return make_fw(ACTIONS, mode="shadow", connectors=[conn], **kw), conn


# ------------------------------------------------------------------------------------------------ engine
def test_shadow_lets_a_would_be_block_run_and_logs_it():
    fw, conn = shadow_fw()
    o = fw.handle(act(amount=500))                       # over max_amount 100: enforcement would BLOCK
    assert o.status == "executed" and len(conn.calls) == 1
    assert o.shadow["would"] == "block" and "exceeds the maximum" in o.shadow["reasons"][0]
    ev = [e for e in fw.ledger.events() if e["event"] == "shadow"]
    assert len(ev) == 1 and ev[0]["data"]["would"] == "block" and ev[0]["data"]["mode"] == "shadow"
    assert fw.ledger.prior_execution(o.idempotency_key)                  # really executed, recorded once


def test_shadow_would_ask_runs_without_creating_a_pending_approval():
    fw, conn = shadow_fw()
    o = fw.handle(act(amount=75))                        # over consent_over_amount 50: enforcement would ASK
    assert o.status == "executed" and o.shadow["would"] == "ask" and len(conn.calls) == 1
    assert fw.ledger.pending() == [] and not [e for e in fw.ledger.events() if e["event"] == "pending"]


def test_shadow_clean_call_logs_no_would_event_under_auto_enforce():
    fw, conn = make_fw(ACTIONS, mode="shadow", connectors=[FakeConnector()]), None
    fw.policy.raw["enforce_mode"] = "auto"
    o = fw.handle(act(amount=10))
    assert o.status == "executed" and o.shadow is None
    assert not [e for e in fw.ledger.events() if e["event"] == "shadow"]


def test_shadow_default_enforce_mode_approval_flags_every_write_but_not_reads():
    fw, conn = shadow_fw()
    w = fw.handle(act(amount=10))
    r = fw.handle(act("fake.read"))
    assert w.shadow["would"] == "ask" and "approval mode" in w.shadow["reasons"][0] and r.shadow is None


def test_shadow_receipts_are_marked_and_keep_the_would_verdict():
    fw, _ = shadow_fw()
    o = fw.handle(act(amount=500))
    r = o.receipt
    assert "mode=shadow" in r["reasons"] and "shadow_would=block" in r["reasons"] and "outcome=executed" in r["reasons"]
    assert r["verdict"] == "BLOCKED"                                  # what enforcement would have decided
    from panel_firewall.firewall.receipts import verify_receipt
    assert verify_receipt(r, fw.signer.pubkey) == []                  # still a valid signed receipt


def test_shadow_receipt_prints_a_notice_in_verify_receipt(tmp_path, capsys):
    fw, _ = shadow_fw()
    r = fw.handle(act(amount=500)).receipt
    f = tmp_path / "r.json"; f.write_text(json.dumps(r))
    from tests.fw_helpers import pubkey_path
    assert main(["verify-receipt", str(f), "--pubkey", pubkey_path()]) == 0
    assert "SHADOW MODE receipt" in capsys.readouterr().out


def test_shadow_agent_sees_no_hint_of_the_would_be_verdict():
    from panel_firewall.firewall.gateway import explain
    fw, _ = shadow_fw()
    o = fw.handle(act(amount=500))
    res = explain(o)
    blob = json.dumps(res)
    assert res["isError"] is False and "BLOCKED" not in blob and "block" not in blob.lower().replace("blocked_", "") and o.verdict.decision == "allow"


def test_shadow_never_turns_itself_into_enforcement():
    fw, conn = shadow_fw()
    for i in range(40):
        fw.handle(act(amount=500 + i))                   # 40 would-be blocks in a row
    assert fw.mode == "shadow" and len(conn.calls) == 40
    assert fw.handle(act(amount=999)).status == "executed"


def test_shadow_still_replays_duplicates_and_does_not_run_twice():
    fw, conn = shadow_fw()
    a = fw.handle(act(amount=500, key="k1")); b = fw.handle(act(amount=500, key="k1"))
    assert a.status == "executed" and b.status == "replayed" and len(conn.calls) == 1


def test_shadow_unknown_tool_still_cannot_run_without_a_connector():
    fw, conn = shadow_fw()
    o = fw.handle(act("nobody.owns.this"))
    assert o.status == "blocked" and not conn.calls


def test_shadow_policy_mode_and_enforce_mode_validation():
    p = parse_policy({"version": "1", "mode": "shadow", "actions": ACTIONS}, "0" * 64)
    assert p.mode == "shadow" and p.enforce_mode == "approval"
    with pytest.raises(FirewallError, match="enforce_mode"):
        parse_policy({"version": "1", "mode": "shadow", "enforce_mode": "shadow", "actions": ACTIONS}, "0" * 64)


# ------------------------------------------------------------------------------------------------ gateway: `proxy --shadow`
def test_proxy_shadow_flag_end_to_end_and_report(rig):  # noqa: F811
    cmd = rig["cmd"][:-2] if False else None
    base = panel_cmd(rig["pol"], rig["ledger"], rig["key"], sys.executable, FAKE, extra=("--shadow",))

    async def go():
        async with McpClient(base, rig["env"]) as c:
            await c.init()
            r = await c.call("pay", {"amount": 100.01})                   # enforcement would block this
            assert r["result"]["isError"] is False and r["result"]["_meta"]["panel"]["status"] == "executed"
            assert "BLOCKED" not in text_of(r)
            r = await c.call("rm_rf_everything", {})                      # not in the policy: would block (upstream may still answer)
    run(go())
    assert "pay" in upstream_calls(rig)                                   # it reached the upstream
    out = subprocess.run([sys.executable, "-m", "panel_firewall.firewall", "report", "--ledger", str(rig["ledger"]), "--policy", str(rig["pol"]),
                          "--since", "48h"], capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1]).stdout
    assert "would have been BLOCKED" in out and "pay" in out and "max_amount" in out and "Nothing below was actually stopped" in out


# ------------------------------------------------------------------------------------------------ report
def test_report_groups_by_tool_and_rule_and_totals_amounts():
    fw, _ = shadow_fw()
    for amt in (500, 600, 150):
        fw.handle(act(amount=amt))
    for amt in (60, 70):
        fw.handle(act(amount=amt))
    fw.handle(act("fake.read"))
    rep = build_report(fw.ledger, 0.0, fw.policy)
    assert rep["actions_seen"] == 6 and rep["would_have_blocked"] == 3 and rep["would_have_asked"] == 2 and rep["unaffected"] == 1
    rows = {(r["tool"], r["rule"], r["would"]): r for r in rep["by_rule"]}
    assert rows[("fake.pay", "max_amount", "block")]["count"] == 3
    assert rows[("fake.pay", "max_amount", "block")]["total_amount"] == 1250
    assert rows[("fake.pay", "consent_over_amount", "ask")]["count"] == 2
    text = format_report(rep, "48h")
    assert "would have been BLOCKED:          3" in text and "Panel never switches itself" in text


def test_report_respects_since_window_and_empty_case():
    clock = [1_000.0]
    fw, _ = shadow_fw(clock=lambda: clock[0])
    fw.handle(act(amount=500))
    clock[0] += 3 * 86400
    fw.handle(act(amount=700))
    rep = build_report(fw.ledger, clock[0] - 48 * 3600, fw.policy)
    assert rep["would_have_blocked"] == 1
    assert "No actions were seen" in format_report(build_report(fw.ledger, clock[0] + 10, fw.policy))


def test_parse_since():
    assert parse_since("48h", 100000) == 100000 - 48 * 3600 and parse_since("7d", 1e6) == 1e6 - 7 * 86400
    with pytest.raises(ValueError):
        parse_since("two days")


def test_every_reason_the_engine_produces_maps_to_a_named_rule():
    from panel_firewall.firewall.policy import LedgerState, evaluate
    from panel_firewall.firewall.types import Action
    rule = {"allowed": True, "required_fields": ["x"], "max_amount": 10, "consent_over_amount": 5, "max_rows": 3,
            "consent_over_rows": 1, "protected": {"path": ["/etc/*"]}, "block_if": [{"field": "q", "op": "eq", "value": 1}],
            "consent_if": [{"field": "z", "op": "eq", "value": 1}], "rate_limit": {"max": 1, "per_seconds": 60},
            "max_total_amount": {"amount": 10, "per_seconds": 60}}
    busy, idle = LedgerState([(time.time(), 9.0)]), LedgerState([])
    cases = [(Action("t", {"amount": 11, "path": "/etc/x", "q": 1, "x": 1}), {"rows": 9}, busy),
             (Action("t", {"amount": 7, "z": 1, "x": 1}), {"rows": 2}, idle),
             (Action("t", {}), {}, idle), (Action("t", {"amount": "a", "x": 1}), {}, idle)]
    seen = set()
    for a, facts, st in cases:
        for r in evaluate(a, rule, facts, st, time.time()).reasons:
            seen.add(rule_of(r)); assert rule_of(r) != "other", r
    assert {"max_amount", "protected", "block_if", "max_rows", "consent_over_amount", "consent_if", "consent_over_rows", "rate_limit",
            "max_total_amount", "required_fields", "amount_field"} <= seen
    assert rule_of("action 'x' is not allowed by policy".replace("action ", "'")) in ("allowed", "other")
    assert rule_of("unknown action 'x': not listed in the policy (default deny)") == "unknown_action"
    assert rule_of("DELETE without a WHERE clause is not allowed") == "sql_guard"


# ------------------------------------------------------------------------------------------------ scrubbing
@pytest.mark.parametrize("text,gone,token", [
    ("mail jane.doe+x@example.co.uk now", "jane.doe+x@example.co.uk", "[email]"),
    ("call +1 (415) 555-0132 today", "555-0132", "[phone]"),
    ("call 415-555-0132 today", "555-0132", "[phone]"),
    ("call +44 20 7946 0958", "7946 0958", "[phone]"),
    ("card 4242 4242 4242 4242 refund", "4242 4242", "[card]"),
    ("card 4242-4242-4242-4242", "4242-4242", "[card]"),
    ("card 4242424242424242", "4242424242424242", "[card]"),
    ("key sk_live_51Habcdefghij1234567890", "sk_live_51Habc", "[secret]"),
    ("token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdef", "[secret]"),
    ("aws AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "[secret]"),
    ("Authorization: Bearer abc123def456ghi789", "abc123def456ghi789", "[secret]"),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r", "eyJhbGci", "[secret]"),
    ("opaque Zk3jD9sLq2Xv8Nw1Rt5Yb7Hc4Pm6Ga0e", "Zk3jD9sLq2Xv8Nw1Rt5Yb7Hc4Pm6Ga0e", "[secret]"),
])
def test_scrub_masks_pii(text, gone, token):
    out = scrub_text(text)
    assert gone not in out and token in out, out


def test_scrub_leaves_hashes_amounts_dates_and_plain_words_alone():
    sha = "a" * 64
    for t in (f"receipt {sha}", "amount 1234.56 on 2026-11-23 at 12:30:45", "order 100234 refunded", "version 1.2.3", "tool stripe.refund",
              "path /data/notes.txt", "rows 1,234,567"):
        assert scrub_text(t) == t, t


def test_scrub_is_recursive_and_keeps_keys():
    out = scrub({"email": "a@b.co", "n": [1, {"k": "call 415-555-0132"}], "ok": True})
    assert out == {"email": "[email]", "n": [1, {"k": "call [phone]"}], "ok": True}


def test_report_and_export_scrub_pii_and_never_include_raw_args_by_default(tmp_path):
    fw, _ = shadow_fw()
    fw.handle(act(amount=500, note="refund jane@example.com card 4242 4242 4242 4242"))
    fw.handle(act(amount=60, who="bob", key=None))
    rep = build_report(fw.ledger, 0.0, fw.policy)
    blob = json.dumps(rep) + format_report(rep)
    rows = export_log(fw.ledger, 0.0, policy=fw.policy)
    allj = json.dumps(rows)
    for secret in ("jane@example.com", "4242 4242", "refund jane"):
        assert secret not in blob and secret not in allj
    assert all("args" not in r for r in rows)
    assert any(r["receipt_sha256"] for r in rows) and any(r["rule"] for r in rows) and any(r["amount"] == 500 for r in rows)
    raw = export_log(fw.ledger, 0.0, include_raw_args=True, policy=fw.policy)
    assert any("jane@example.com" in json.dumps(r.get("args", {})) for r in raw)       # only with the flag


def test_cli_export_log_and_export_receipts_scrub(tmp_path, capsys):
    from panel_firewall.firewall.ledger import Ledger
    led = tmp_path / "l.sqlite"
    fw, _ = shadow_fw()
    from panel_firewall.firewall.engine import Firewall
    from tests.fw_helpers import signer
    fw = Firewall(policy(ACTIONS, "shadow"), Ledger(led), signer(), [FakeConnector()])
    fw.handle(act(amount=500, note="x@y.com"))
    out = tmp_path / "log.jsonl"
    assert main(["export-log", "--ledger", str(led), "--out", str(out)]) == 0
    text = out.read_text()
    assert "x@y.com" not in text and "no raw arguments" in capsys.readouterr().out
    assert main(["export-log", "--ledger", str(led), "--out", str(out), "--include-raw-args"]) == 0
    assert "x@y.com" in out.read_text() and "RAW ARGUMENTS INCLUDED" in capsys.readouterr().out
    rc = tmp_path / "r.json"
    assert main(["export-receipts", "--ledger", str(led), "--out", str(rc), "--scrub"]) == 0
    assert json.loads(rc.read_text())[0]["scrubbed"] is True
