"""Approval PIN: hashed storage, lockout, single-use action-bound tokens, CLI refuses without a human at a terminal, UI form."""
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from panel_firewall.firewall.cli import main
from panel_firewall.firewall.config import build_firewall
from panel_firewall.firewall.pin import MAX_FAILURES, ApprovalGate, PinError, PinStore
from panel_firewall.firewall.types import Action
from panel_firewall.firewall.ui import start_background
from tests.fw_helpers import act, make_fw
from tests.pty_helpers import panel, run_on_tty
from tests.test_fw_ui import req

ROOT = Path(__file__).resolve().parents[1]
PIN = "correct horse"


class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t


@pytest.fixture
def store(tmp_path):
    clk = Clock()
    st = PinStore(tmp_path / "pin.json", clock=clk)
    st.set_pin(PIN, n=2 ** 10)
    st.clk = clk
    return st


def held(fw, **kw):
    o = fw.handle(act(amount=75, **kw))
    assert o.status == "needs_consent"
    return o


# ------------------------------------------------------------------------------------------------ storage + lockout
def test_only_a_salted_hash_is_stored_mode_600(store):
    raw = store.path.read_text()
    assert PIN not in raw and json.loads(raw)["kdf"] == "scrypt" and json.loads(raw)["salt"]
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    other = PinStore(store.path.parent / "p2.json"); other.set_pin(PIN, n=2 ** 10)
    assert json.loads(other.path.read_text())["hash"] != json.loads(raw)["hash"]       # salted


def test_short_pin_refused_and_change_needs_current(store):
    with pytest.raises(PinError, match="at least"):
        PinStore(store.path.parent / "x.json").set_pin("abc")
    with pytest.raises(PinError, match="wrong PIN"):
        store.set_pin("another one 1", current_pin="nope nope")
    store.set_pin("another one 1", current_pin=PIN, n=2 ** 10)
    store.verify("another one 1")


def test_wrong_pin_lockout_then_expiry_and_reset(store):
    for i in range(MAX_FAILURES - 1):
        with pytest.raises(PinError, match="wrong PIN"):
            store.verify("bad guess")
    with pytest.raises(PinError, match="locked") as e:
        store.verify("bad guess")
    assert e.value.locked_for > 0
    with pytest.raises(PinError, match="locked"):
        store.verify(PIN)                           # even the right PIN is refused while locked
    store.clk.t += 301
    for i in range(MAX_FAILURES):                   # lock expired, guess wrong again: the next lockout doubles
        with pytest.raises(PinError):
            store.verify("bad guess")
    assert store.status()["locked_for"] > 500
    store.clk.t += 601
    store.verify(PIN)                               # success clears the counters
    assert store.status()["failures"] == 0 and store.status()["locked_for"] == 0


def test_lockout_survives_a_new_process(store):
    for _ in range(MAX_FAILURES):
        with pytest.raises(PinError):
            store.verify("bad guess")
    with pytest.raises(PinError, match="locked"):
        PinStore(store.path, clock=store.clk).verify(PIN)


def test_no_pin_set_refuses(tmp_path):
    with pytest.raises(PinError, match="no approval PIN"):
        PinStore(tmp_path / "none.json").verify("anything")


# ------------------------------------------------------------------------------------------------ tokens
def test_ledger_with_guard_refuses_approval_without_token_but_allows_deny(store):
    fw = make_fw(); ApprovalGate(fw.ledger, store)
    o = held(fw)
    ok, msg = fw.ledger.approve(o.approval_id, "agent")
    assert not ok and "token" in msg
    assert fw.handle(act(amount=75)).status == "needs_consent"
    assert fw.ledger.approve(o.approval_id, "human", deny=True)[0]            # refusing is always allowed


def test_gate_approval_runs_action_once_and_records_proof(store):
    fw = make_fw(); gate = ApprovalGate(fw.ledger, store)
    o = held(fw)
    with pytest.raises(PinError):
        gate.decide(o.approval_id, "human", None)
    assert gate.decide(o.approval_id, "human", PIN) == (True, "approved")
    ev = [e for e in fw.ledger.events() if e["event"] == "approved"][0]["data"]
    assert ev["pin_verified"] is True and ev["token_nonce"]
    assert fw.handle(act(amount=75)).status == "executed"


def test_token_is_bound_to_the_exact_action(store):
    fw = make_fw(); ApprovalGate(fw.ledger, store)
    a, b = held(fw), fw.handle(act(amount=80))
    sha_a = fw.ledger.pending_action_sha(a.approval_id)
    tok = store.mint(a.approval_id, sha_a)
    ok, msg = fw.ledger.approve(b.approval_id, "h", token=tok)             # token for A used on B
    assert not ok and "different action" in msg
    forged = dict(tok, action_sha=fw.ledger.pending_action_sha(b.approval_id))
    assert not fw.ledger.approve(b.approval_id, "h", token=forged)[0]       # editing the token breaks its MAC
    assert fw.ledger.approve(a.approval_id, "h", token=tok)[0]


def test_token_is_single_use(store):
    fw = make_fw(); ApprovalGate(fw.ledger, store)
    a = held(fw)
    tok = store.mint(a.approval_id, fw.ledger.pending_action_sha(a.approval_id))
    assert fw.ledger.approve(a.approval_id, "h", token=tok)[0]
    # same nonce on a different pending action (even if it were bound to it) is refused: the nonce is recorded
    b = fw.handle(act(amount=81))
    tok_b = dict(tok)
    assert not fw.ledger.approve(b.approval_id, "h", token=tok_b)[0]
    # nonce replay check itself: re-use after the event exists
    led = fw.ledger
    assert led._db.execute("SELECT count(*) FROM events WHERE json_extract(data,'$.token_nonce')=?", (tok["nonce"],)).fetchone()[0] == 1


def test_token_expires(store):
    fw = make_fw(); ApprovalGate(fw.ledger, store)
    a = held(fw)
    tok = store.mint(a.approval_id, fw.ledger.pending_action_sha(a.approval_id))
    store.clk.t += 61
    ok, msg = fw.ledger.approve(a.approval_id, "h", token=tok)
    assert not ok and "expired" in msg


def test_deny_token_cannot_approve(store):
    fw = make_fw(); ApprovalGate(fw.ledger, store)
    a = held(fw)
    tok = store.mint(a.approval_id, fw.ledger.pending_action_sha(a.approval_id), deny=True)
    assert not fw.ledger.approve(a.approval_id, "h", token=tok)[0]


# ------------------------------------------------------------------------------------------------ CLI
@pytest.fixture
def cli(tmp_path):
    key = tmp_path / "k.pem"
    assert main(["keygen", "--path", str(key)]) == 0
    pol = tmp_path / "p.yaml"
    pol.write_text(yaml.safe_dump({"version": "7", "mode": "auto", "actions": {"sql.query": {"max_rows": 5, "consent_over_rows": 1}},
                                   "connectors": [{"type": "sqlite", "path": "app.db"}]}))
    import sqlite3
    con = sqlite3.connect(tmp_path / "app.db"); con.execute("CREATE TABLE t(id INTEGER)")
    con.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(4)]); con.commit(); con.close()
    fw = build_firewall(str(pol), key=str(key))
    o = fw.handle(Action("sql.query", {"sql": "DELETE FROM t WHERE id < 3"}, "c"))
    assert o.status == "needs_consent"
    pf = tmp_path / "pin.json"
    PinStore(pf).set_pin(PIN, n=2 ** 10)
    argv = panel("approve", o.approval_id, "--policy", str(pol), "--pin-file", str(pf), "--who", "dana")
    return fw, o, argv, pf


def still_pending(fw, o):
    return fw.ledger.consent_state(o.idempotency_key) == "pending"


def test_cli_approve_via_stdin_pipe_refused(cli):
    fw, o, argv, _ = cli
    r = subprocess.run(argv, input=PIN + "\n", capture_output=True, text=True, cwd=ROOT, timeout=30)
    assert r.returncode == 1 and "interactive terminal" in r.stdout + r.stderr
    assert still_pending(fw, o)


def test_cli_approve_pin_in_env_or_args_is_ignored(cli):
    fw, o, argv, _ = cli
    r = subprocess.run(argv + [PIN], input="", capture_output=True, text=True, cwd=ROOT, timeout=30,
                       env={**os.environ, "PANEL_PIN": PIN, "PIN": PIN, "PANEL_APPROVAL_PIN": PIN})
    assert r.returncode != 0 and still_pending(fw, o)


def test_cli_approve_with_no_tty_refused(cli):
    fw, o, argv, _ = cli
    r = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, cwd=ROOT, timeout=30, start_new_session=True)
    assert r.returncode == 1 and "terminal" in r.stdout + r.stderr
    assert still_pending(fw, o)


def test_cli_approve_piped_stdout_refused_even_with_a_pty_stdin(cli):
    """An agent that inherited the human's terminal as stdin but captures stdout is still refused."""
    fw, o, argv, _ = cli
    import pty
    master, slave = pty.openpty()
    r = subprocess.run(argv, stdin=slave, capture_output=True, text=True, cwd=ROOT, timeout=30)
    os.close(master); os.close(slave)
    assert r.returncode == 1 and "interactive terminal" in r.stdout and still_pending(fw, o)


def test_cli_approve_with_human_at_a_terminal_works(cli):
    fw, o, argv, _ = cli
    code, out = run_on_tty(argv, [PIN], cwd=ROOT)
    assert code == 0 and "OK: approved by dana" in out and PIN not in out, out        # echo is off
    assert not still_pending(fw, o)
    assert fw.handle(Action("sql.query", {"sql": "DELETE FROM t WHERE id < 3"}, "c")).status == "executed"


def test_cli_wrong_pin_then_lockout(cli):
    fw, o, argv, pf = cli
    for i in range(MAX_FAILURES):
        code, out = run_on_tty(argv, ["wrong pin!"], cwd=ROOT)
        assert code == 1 and "NOT DONE" in out
    code, out = run_on_tty(argv, [PIN], cwd=ROOT)
    assert code == 1 and "locked" in out and still_pending(fw, o)         # the correct PIN is refused during the lockout


def test_cli_approve_refused_when_no_pin_is_set(cli, tmp_path):
    fw, o, argv, _ = cli
    argv = argv[:-4] + ["--pin-file", str(tmp_path / "missing.json"), "--who", "dana"]
    code, out = run_on_tty(argv, [PIN], cwd=ROOT)
    assert code == 1 and "no approval PIN" in out and still_pending(fw, o)


def test_cli_deny_needs_no_pin(cli):
    fw, o, _, pf = cli
    r = subprocess.run(panel("deny", o.approval_id, "--policy", str(Path(fw.policy.path)), "--pin-file", str(pf), "--who", "dana"),
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, cwd=ROOT, timeout=30, start_new_session=True)
    assert r.returncode == 0 and "OK: denied" in r.stdout


def test_pin_set_only_from_a_terminal(tmp_path):
    pf = tmp_path / "pin.json"
    r = subprocess.run(panel("pin", "set", "--pin-file", str(pf)), input="longenough\nlongenough\n", capture_output=True, text=True,
                       cwd=ROOT, timeout=30, start_new_session=True)
    assert r.returncode == 1 and not pf.exists()
    code, out = run_on_tty(panel("pin", "set", "--pin-file", str(pf)), ["longenough", "longenough"], cwd=ROOT)
    assert code == 0 and pf.exists() and "longenough" not in pf.read_text()
    code, out = run_on_tty(panel("pin", "set", "--pin-file", str(pf)), ["longenough", "newpin1234", "different!"], cwd=ROOT)
    assert code == 1 and "differ" in out
    r = subprocess.run(panel("pin", "status", "--pin-file", str(pf)), capture_output=True, text=True, cwd=ROOT, timeout=30)
    assert "PIN set" in r.stdout and "not locked" in r.stdout


# ------------------------------------------------------------------------------------------------ UI
def test_ui_approve_needs_the_pin(store):
    fw = make_fw(); srv = start_background(fw.ledger, 0, "h", store)
    try:
        o = held(fw)
        path = f"/api/approve/{o.approval_id}"
        assert req(srv, path, "POST", body={})[0] == 403                    # no PIN
        assert req(srv, path, "POST", body={"pin": ""})[0] == 403
        c, b = req(srv, path, "POST", body={"pin": "wrong wrong"})
        assert c == 403 and "wrong PIN" in b["message"]
        assert fw.handle(act(amount=75)).status == "needs_consent"
        assert req(srv, path, "POST", body={"pin": PIN})[0] == 200
        assert fw.handle(act(amount=75)).status == "executed"
    finally:
        srv.shutdown()


def test_ui_refuses_when_no_pin_is_set(tmp_path):
    fw = make_fw(); srv = start_background(fw.ledger, 0, "h", PinStore(tmp_path / "none.json"))
    try:
        o = held(fw)
        c, b = req(srv, f"/api/approve/{o.approval_id}", "POST", body={"pin": "whatever1"})
        assert c == 403 and "no approval PIN" in b["message"]
        assert fw.ledger.consent_state(o.idempotency_key) == "pending"
    finally:
        srv.shutdown()


def test_ui_lockout_returns_429_and_blocks_the_right_pin(store):
    fw = make_fw(); srv = start_background(fw.ledger, 0, "h", store)
    try:
        o = held(fw)
        path = f"/api/approve/{o.approval_id}"
        codes = [req(srv, path, "POST", body={"pin": "wrong wrong"})[0] for _ in range(MAX_FAILURES)]
        assert codes[-1] == 429
        c, b = req(srv, path, "POST", body={"pin": PIN})
        assert c == 429 and b["retry_after"] > 0
        assert fw.ledger.consent_state(o.idempotency_key) == "pending"
    finally:
        srv.shutdown()


def test_ui_deny_needs_no_pin_and_page_has_a_pin_field(store):
    from panel_firewall.firewall.ui import PAGE
    assert "type='password'" in PAGE or 'type="password"' in PAGE or "pin.type='password'" in PAGE
    fw = make_fw(); srv = start_background(fw.ledger, 0, "h", store)
    try:
        o = held(fw)
        assert req(srv, f"/api/deny/{o.approval_id}", "POST", body={})[0] == 200
    finally:
        srv.shutdown()
