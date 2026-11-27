"""Opt-in anonymized exploit telemetry: signatures, the local log, the CLI and the cloud batch upload."""
import json

from panel_firewall.firewall import telemetry
from panel_firewall.firewall.claims import check_reply
from panel_firewall.firewall.cloud import CloudError, CloudSync
from panel_firewall.firewall.connector import Connector
from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from panel_firewall.firewall.types import ActionSchema, Result
from tests.fw_helpers import act, policy, signer

NOW = 1_700_000_000.0                      # 2023-11-14 22:13:20 UTC
RAW_TOOL = "refunds.create"


class Refunds(Connector):
    name = "refunds"

    def __init__(self):
        self.calls = []

    def describe_actions(self):
        return [ActionSchema(RAW_TOOL, "refund", {"amount": {"type": "number"}}, (), "write")]

    def execute(self, action, mode):
        self.calls.append(action)
        return Result(True, f"id-{len(self.calls)}", {})


def fw_for(rule, telemetry_on=True, mode="auto", **top):
    top = {**top, **({"telemetry": True} if telemetry_on else {})}
    led = Ledger(":memory:", clock=lambda: NOW)
    return Firewall(policy({RAW_TOOL: rule}, mode, **top), led, signer(), [Refunds()], clock=lambda: NOW)


def sigs(fw):
    return telemetry.ExploitLog(fw.ledger).since(0)


def test_over_max_amount_is_cap_split_with_ratio():
    fw = fw_for({"max_amount": 100})
    assert fw.handle(act(RAW_TOOL, amount=200)).status == "blocked"
    [s] = sigs(fw)
    assert (s.pattern_type, s.rule_triggered, s.tool_category, s.verdict) == ("cap_split", "max_amount", "payment", "block")
    assert s.amount_ratio == 2.0


def test_rate_limited_call_is_velocity_burst_with_window_position_and_spread():
    fw = fw_for({"rate_limit": {"max": 2, "per_seconds": 3600}})
    assert fw.handle(act(RAW_TOOL, "c1", amount=1)).status == "executed"
    assert fw.handle(act(RAW_TOOL, "c2", amount=2)).status == "executed"
    assert fw.handle(act(RAW_TOOL, "c3", amount=3)).status == "blocked"
    [s] = sigs(fw)
    assert s.pattern_type == "velocity_burst" and s.rule_triggered == "rate_limit"
    assert s.window_position == "2nd of 2 allowed" and s.session_spread == 3      # c1, c2 and the blocked c3


def test_entity_velocity_and_outflow_map_to_patterns():
    fw = fw_for({"entity_velocity": {"field": "customer_id", "max_actions": 1, "per_seconds": 3600}})
    fw.handle(act(RAW_TOOL, "c1", customer_id="cus_9", amount=1))
    fw.handle(act(RAW_TOOL, "c2", customer_id="cus_9", amount=2))
    [s] = sigs(fw)
    assert s.pattern_type == "velocity_burst" and s.rule_triggered == "entity_velocity" and s.window_position == "1st of 1 allowed"
    assert s.session_spread == 2
    fw = fw_for({}, max_total_outflow={"amount": 100, "per_seconds": 3600, "tools": [RAW_TOOL]})
    fw.handle(act(RAW_TOOL, amount=150))
    [s] = sigs(fw)
    assert (s.pattern_type, s.rule_triggered, s.amount_ratio) == ("cap_split", "max_total_outflow", 1.5)


def test_false_completion_claim():
    fw = fw_for({"max_amount": 100})
    r = check_reply("I've refunded $50 to your card.", fw.ledger, "conv-1", fw.policy)
    assert not r.ok
    [s] = sigs(fw)
    assert s.pattern_type == "false_completion" and s.tool_category == "payment" and s.verdict == "block"


def test_hold_and_forbidden_tool_and_breaker_trip():
    fw = fw_for({"max_amount": 100, "consent_over_amount": 50})
    assert fw.handle(act(RAW_TOOL, amount=75)).status == "needs_consent"
    fw.handle(act(RAW_TOOL, amount=75))                                  # polling the same held action adds nothing
    [s] = sigs(fw)
    assert (s.verdict, s.pattern_type, s.amount_ratio) == ("needs_consent", "cap_split", 1.5)
    fw = fw_for({"max_amount": 100})
    fw.handle(act("payments.wire", amount=1))                            # not in the policy
    assert sigs(fw)[0].pattern_type == "forbidden_tool"
    fw = fw_for({"max_amount": 1}, circuit_breaker={"blocks": 2, "per_seconds": 60})
    fw.handle(act(RAW_TOOL, amount=5))
    fw.handle(act(RAW_TOOL, amount=6))
    assert "circuit_breaker_trip" in {s.pattern_type for s in sigs(fw)}


def test_sql_rule_maps_to_sql_injection():
    assert telemetry.pattern_for("sql_guard") == "sql_injection"
    assert telemetry.tool_category("db.run_query") == "database" and telemetry.tool_category("fs.read_file") == "filesystem"
    assert telemetry.tool_category("slack.post_message") == "communication" and telemetry.tool_category("mystery") == "other"


def test_signatures_never_contain_raw_names_amounts_args_or_ids():
    fw = fw_for({"max_amount": 100, "rate_limit": {"max": 1, "per_seconds": 3600}})
    fw.handle(act(RAW_TOOL, "conv-SECRET-1", amount=4, note="alice@example.com", customer_id="cus_SECRET"))
    fw.handle(act(RAW_TOOL, "conv-SECRET-2", amount=777.77, note="alice@example.com", customer_id="cus_SECRET"))
    fw.handle(act("payments.wire", "conv-SECRET-3", amount=999.99, api_key="sk_live_SECRET"))
    check_reply("Done, I refunded $777.77 to alice@example.com", fw.ledger, "conv-SECRET-4", fw.policy)
    found = sigs(fw)
    assert len(found) >= 3
    blob = json.dumps([s.to_dict() for s in found]) + json.dumps(fw.ledger._rows("SELECT * FROM exploit_signatures"))
    for leak in (RAW_TOOL, "refunds", "payments", "wire", "777.77", "999.99", "SECRET", "alice", "example.com", "sk_live", "conv-", "note", "customer_id"):
        assert leak not in blob, leak
    assert set(found[0].to_dict()) == {"pattern_type", "tool_category", "rule_triggered", "amount_ratio", "window_position",
                                       "session_spread", "timestamp_bucket", "verdict"}
    assert all(s.timestamp_bucket % 3600 == 0 for s in found)


def test_local_log_stores_and_retrieves():
    led = Ledger(":memory:")
    log = telemetry.ExploitLog(led)
    a = telemetry.build_signature(rule="max_amount", tool=RAW_TOOL, verdict="block", ts=NOW, ratio=2.0)
    b = telemetry.build_signature(rule="rate_limit", tool="slack.send", verdict="block", ts=NOW - 3 * 86400, position="5th of 5 allowed", spread=3)
    log.add(a)
    log.add(b)
    assert log.since(0) == [a, b]
    assert log.since(NOW - 86400) == [a]                                  # --since filters on the hour bucket
    sm = telemetry.summarize(log.since(0))
    assert sm["total"] == 2 and sm["by_pattern"] == {"cap_split": 1, "velocity_burst": 1} and sm["max_amount_ratio"] == 2.0 and sm["max_session_spread"] == 3
    assert "2 exploit pattern(s)" in telemetry.format_summary(sm)


def test_off_by_default():
    fw = fw_for({"max_amount": 100}, telemetry_on=False)
    assert fw.handle(act(RAW_TOOL, amount=500)).status == "blocked"
    check_reply("I've refunded $50.", fw.ledger, "c", fw.policy)
    assert sigs(fw) == []
    fw2 = fw_for({"max_amount": 100}, telemetry_on=False, telemetry=False)
    fw2.handle(act(RAW_TOOL, amount=500))
    assert sigs(fw2) == []


def test_shadow_mode_records_nothing():
    fw = fw_for({"max_amount": 100}, mode="shadow")
    fw.handle(act(RAW_TOOL, amount=500))
    assert sigs(fw) == []


def test_policy_telemetry_must_be_boolean():
    import pytest

    from panel_firewall.firewall.types import FirewallError
    with pytest.raises(FirewallError):
        policy({RAW_TOOL: {}}, "auto", telemetry="yes")


# ------------------------------------------------------------------ cloud upload + CLI
class FakeClient:
    def __init__(self, fail=False):
        self.batches, self.fail = [], fail

    def telemetry_exploits(self, signatures):
        if self.fail:
            raise CloudError("cloud error 404: ")
        self.batches.append(signatures)
        return {}


def sync_for(fw, client, clock):
    s = CloudSync.__new__(CloudSync)
    s.client, s.fw, s.clock, s._last_telemetry = client, fw, clock, 0.0
    return s


def test_cloud_upload_batches_every_five_minutes_and_only_when_enabled():
    t = [NOW]
    fw = fw_for({"max_amount": 100})
    fw.handle(act(RAW_TOOL, amount=500))
    client = FakeClient()
    s = sync_for(fw, client, lambda: t[0])
    assert s.upload_telemetry() == 1 and len(client.batches) == 1
    assert set(client.batches[0][0]) == {"pattern_type", "tool_category", "rule_triggered", "amount_ratio", "window_position",
                                         "session_spread", "timestamp_bucket", "verdict"}
    fw.handle(act(RAW_TOOL, amount=600))
    t[0] += 60
    assert s.upload_telemetry() == 0                                      # under 5 minutes since the last batch
    t[0] += 300
    assert s.upload_telemetry() == 1 and len(client.batches) == 2         # only the new one; the first is not re-sent
    off = fw_for({"max_amount": 100}, telemetry_on=False)
    assert sync_for(off, FakeClient(), lambda: NOW).upload_telemetry() == 0


def test_cloud_upload_failure_keeps_signatures_for_retry():
    t = [NOW]
    fw = fw_for({"max_amount": 100})
    fw.handle(act(RAW_TOOL, amount=500))
    s = sync_for(fw, FakeClient(fail=True), lambda: t[0])
    assert s.upload_telemetry() == 0
    s.client, t[0] = FakeClient(), t[0] + 301
    assert s.upload_telemetry() == 1


def test_cli_exploits_and_threats(tmp_path, capsys, monkeypatch):
    from panel_firewall.firewall.cli import main
    db = tmp_path / "l.db"
    led = Ledger(db)
    telemetry.ExploitLog(led).add(telemetry.build_signature(rule="max_amount", tool=RAW_TOOL, verdict="block", ts=__import__("time").time(), ratio=3.0))
    led._db.close()
    assert main(["exploits", "--ledger", str(db), "--since", "24h"]) == 0
    out = capsys.readouterr().out
    assert "1 exploit pattern(s)" in out and "cap_split" in out and "3x the limit" in out and RAW_TOOL not in out
    assert main(["threats"]) == 0
    assert capsys.readouterr().out.strip() == "Threat feed requires Panel Cloud. Run with --cloud-url to connect."
