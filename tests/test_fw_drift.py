"""Baseline drift: this week's traffic against last week's, printed by `usepanel report`."""
import time

from panel_firewall.firewall import drift
from panel_firewall.firewall.cli import main
from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from panel_firewall.firewall.summary import build_report, format_report
from tests.fw_helpers import FakeConnector, act, policy, signer


def calls(tool, n, amount=None, **args):
    return [{"ts": 0.0, "conv": f"c{i}", "tool": tool, "args": dict(args), "amount": amount} for i in range(n)]


def test_average_amount_shift_is_reported_with_the_percentage():
    f = drift.compare(calls("refunds.create", 20, 89.0), calls("refunds.create", 20, 45.0))
    assert [x["text"] for x in f] == ["refunds.create: average amount shifted from $45 to $89 (98% increase)"]
    f = drift.compare(calls("refunds.create", 20, 20.0), calls("refunds.create", 20, 45.0))
    assert "decrease" in f[0]["text"]


def test_small_shifts_and_identical_weeks_are_silent():
    assert drift.compare(calls("t", 20, 50.0), calls("t", 20, 45.0)) == []
    assert drift.compare(calls("t", 20, 45.0, status="ok"), calls("t", 20, 45.0, status="ok")) == []


def test_volume_doubling_and_a_new_tool():
    f = drift.compare(calls("a", 40, 1.0) + calls("b", 3), calls("a", 20, 1.0))
    kinds = {(x["tool"], x["kind"]) for x in f}
    assert ("a", "frequency") in kinds and ("b", "new_tool") in kinds


def test_new_argument_values_for_a_small_vocabulary_field():
    prior = calls("t", 15, 1.0, status="open") + calls("t", 15, 1.0, status="closed")
    cur = calls("t", 15, 1.0, status="open") + calls("t", 5, 1.0, status="refunded")
    f = [x for x in drift.compare(cur, prior) if x["kind"] == "values"]
    assert len(f) == 1 and "1 new value(s) for 'status'" in f[0]["text"] and "refunded" in f[0]["text"]


def test_new_sql_patterns_are_normalised_so_literals_do_not_count():
    prior = calls("db.query", 12, sql="SELECT * FROM orders WHERE id = 5")
    same = [{**c, "args": {"sql": f"select * from orders where id = {i}  "}} for i, c in enumerate(calls("db.query", 12))]
    assert drift.compare(same, prior) == []
    cur = same + [{**c, "args": {"sql": s}} for c, s in zip(calls("db.query", 3), ["DELETE FROM orders", "DROP TABLE x", "SELECT password FROM users WHERE name='bob'"])]
    f = [x for x in drift.compare(cur, prior) if x["kind"] == "sql"]
    assert f and f[0]["text"] == "db.query: 3 new SQL pattern(s) not seen in the prior baseline"


def test_too_little_history_is_not_drift():
    assert drift.compare(calls("t", 5, 100.0), calls("t", 5, 1.0)) == []
    assert drift.compare([], calls("t", 20, 1.0)) == []


def test_format_includes_the_recommendation():
    text = drift.format_drift([{"tool": "t", "kind": "amount", "text": "t: average amount shifted"}])
    assert text.startswith("Baseline drift detected:") and "Recommendation: review policy rules and run `usepanel suggest`" in text
    assert drift.format_drift([]) == ""


def seeded(path=":memory:"):
    """Last week: refunds of ~$45. This week: ~$89."""
    now = time.time()
    t = [now - 12 * 86400]
    pol = policy({"fake.pay": {"risk": "write"}}, "shadow")
    fw = Firewall(pol, Ledger(path, clock=lambda: t[0]), signer(), [FakeConnector()], clock=lambda: t[0])
    for i in range(30):
        t[0] = now - 12 * 86400 + i * 3600
        fw.handle(act(conv=f"p{i}", amount=45))
    for i in range(30):
        t[0] = now - 4 * 86400 + i * 3600
        fw.handle(act(conv=f"n{i}", amount=89))
    return fw


def test_detect_and_report_use_the_ledger_history():
    fw = seeded()
    f = drift.detect(fw.ledger, time.time())
    assert any(x["kind"] == "amount" and "from $45 to $89" in x["text"] for x in f)
    rep = build_report(fw.ledger, 0, fw.policy)
    assert rep["drift"] and "Baseline drift detected:" in format_report(rep) and "Recommendation" in format_report(rep)


def test_report_cli_prints_the_drift_warning(tmp_path, capsys):
    db = str(tmp_path / "l.sqlite")
    seeded(db)
    import yaml
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({"version": "t", "mode": "shadow", "actions": {"fake.pay": {"risk": "write"}}}))
    assert main(["report", "--policy", str(p), "--ledger", db, "--since", "30d"]) == 0
    assert "Baseline drift detected:" in capsys.readouterr().out
