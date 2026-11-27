"""CLI: keygen outside repo, approve/deny/pending against a shared ledger, verify-receipt, start refuses without a key."""
import json
from pathlib import Path

import pytest
import yaml

from panel_firewall.firewall.cli import main
from panel_firewall.firewall.config import build_firewall
from panel_firewall.firewall.types import Action, FirewallError

ROOT = Path(__file__).resolve().parents[1]
from tests.fw_helpers import IN_GIT_CHECKOUT, NOT_IN_GIT_REASON


@pytest.fixture
def env(tmp_path):
    key = tmp_path / "k.pem"
    assert main(["keygen", "--path", str(key)]) == 0
    pol = tmp_path / "p.yaml"
    pol.write_text(yaml.safe_dump({"version": "7", "mode": "auto", "actions": {"sql.query": {"max_rows": 5, "consent_over_rows": 1}},
                                   "connectors": [{"type": "sqlite", "path": "app.db"}]}))
    import sqlite3
    con = sqlite3.connect(tmp_path / "app.db"); con.execute("CREATE TABLE t(id INTEGER, v TEXT)")
    con.executemany("INSERT INTO t VALUES (?,?)", [(i, "x") for i in range(4)]); con.commit(); con.close()
    return tmp_path, key, pol


def test_build_refuses_without_key(env, tmp_path):
    _, key, pol = env
    with pytest.raises(FirewallError, match="keygen"):
        build_firewall(str(pol), key=str(tmp_path / "nokey.pem"))


def test_cli_approve_flow_in_a_second_process_and_verify(env, capsys):
    tmp, key, pol = env
    fw = build_firewall(str(pol), key=str(key))
    o = fw.handle(Action("sql.query", {"sql": "DELETE FROM t WHERE id < 3"}, "c"))
    assert o.status == "needs_consent"
    from panel_firewall.firewall.pin import PinStore
    PinStore(tmp / "pin.json").set_pin("correct horse", n=2 ** 10)
    from tests.pty_helpers import panel, run_on_tty
    code, out = run_on_tty(panel("approve", o.approval_id, "--policy", str(pol), "--who", "dana", "--pin-file", str(tmp / "pin.json")),
                           ["correct horse"], cwd=ROOT)
    assert code == 0 and "OK: approved by dana" in out, out
    o2 = fw.handle(Action("sql.query", {"sql": "DELETE FROM t WHERE id < 3"}, "c"))
    assert o2.status == "executed" and "approved_by=dana" in o2.receipt["reasons"]
    f = tmp / "r.json"; f.write_text(json.dumps(o2.receipt))
    assert main(["verify-receipt", str(f), "--pubkey", str(key) + ".pub", "--policy", str(pol)]) == 0
    assert "does NOT prove" in capsys.readouterr().out
    tampered = json.loads(f.read_text()); tampered["verdict"] = "BLOCKED"; f.write_text(json.dumps(tampered))
    assert main(["verify-receipt", str(f), "--pubkey", str(key) + ".pub"]) == 1
    pol.write_text(pol.read_text() + "\n# edited\n")
    f.write_text(json.dumps(o2.receipt))
    assert main(["verify-receipt", str(f), "--pubkey", str(key) + ".pub", "--policy", str(pol)]) == 1


def test_cli_deny_and_pending(env, capsys):
    tmp, key, pol = env
    fw = build_firewall(str(pol), key=str(key))
    o = fw.handle(Action("sql.query", {"sql": "DELETE FROM t WHERE id < 3"}, "c"))
    assert main(["pending", "--policy", str(pol)]) == 0 and o.approval_id in capsys.readouterr().out
    assert main(["deny", o.approval_id, "--policy", str(pol), "--who", "e"]) == 0
    assert main(["approve", o.approval_id, "--policy", str(pol), "--who", "e", "--pin-file", str(tmp / "nopin.json")]) == 1
    assert fw.handle(Action("sql.query", {"sql": "DELETE FROM t WHERE id < 3"}, "c")).status == "blocked"


@pytest.mark.skipif(not IN_GIT_CHECKOUT, reason=NOT_IN_GIT_REASON)
def test_keygen_refuses_inside_repo(capsys):
    assert main(["keygen", "--path", str(ROOT / "oops.pem")]) == 2
    assert not (ROOT / "oops.pem").exists()


# ------------------------------------------------------------------------------------------------ Ctrl+C
def test_keyboard_interrupt_exits_cleanly_with_one_line(capsys, monkeypatch):
    from panel_firewall.firewall import cli
    monkeypatch.setattr(cli, "cmd_demo", lambda a: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert cli.main(["demo"]) == 0
    err = capsys.readouterr().err
    assert err.strip() == "Panel stopped." and "Traceback" not in err


def test_ctrl_c_on_a_running_proxy_exits_zero_without_a_traceback(tmp_path):
    import signal
    import subprocess
    import sys
    import time
    from pathlib import Path

    from panel_firewall.firewall.receipts import generate_key
    from tests.fw_helpers import panel_cmd, write_policy
    key = generate_key(tmp_path / "k.pem")
    pol = write_policy(tmp_path, {"echo": {"risk": "read"}})
    fake = str(Path(__file__).parent / "support" / "fake_mcp_server.py")
    p = subprocess.Popen(panel_cmd(pol, tmp_path / "l.sqlite", key, sys.executable, fake), stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=Path(__file__).resolve().parents[1])
    time.sleep(2.5)
    p.send_signal(signal.SIGINT)
    try:
        out, err = p.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
        raise
    assert p.returncode == 0, err.decode()
    assert b"Traceback" not in err and err.decode().strip().splitlines()[-1] == "Panel stopped."
