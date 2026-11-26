"""Clean one-line errors: a missing upstream command, and row counting that cannot work (no `database:` / unreadable path)."""
import subprocess
import sys

from panel_firewall.firewall import sqlguard
from panel_firewall.firewall.cli import main
from panel_firewall.firewall.connectors.mcp_upstream import McpUpstreamConnector
from panel_firewall.firewall.policy import parse_policy
from panel_firewall.firewall.types import Action

NO_DB = "Set database: in your policy to enable row counting for SQL writes. Without it, all SQL writes are blocked."
DELETE = Action("q", {"query": "DELETE FROM orders WHERE id=1"})


def _reasons(raw):
    pol = parse_policy({"actions": {"q": {"sql_arg": "query"}}, **raw})
    return McpUpstreamConnector(pol, lambda *a: None).facts(DELETE, pol)["block_reasons"]


def test_init_with_missing_upstream_is_one_clean_line(tmp_path, capsys):
    rc = main(["init", "--out", str(tmp_path / "p.yaml"), "--", "/nonexistent/server"])
    err = capsys.readouterr().err
    assert rc == 1 and err.strip() == "Error: command not found at /nonexistent/server" and "Traceback" not in err


def test_proxy_with_missing_upstream_is_one_clean_line(tmp_path):
    pol = tmp_path / "p.yaml"
    pol.write_text('{"version": "1", "reviewed": true, "mode": "approval", "actions": {"a": {"risk": "read"}}}')
    key = tmp_path / "k.pem"
    subprocess.run([sys.executable, "-m", "panel_firewall.firewall", "keygen", "--path", str(key)], check=True, capture_output=True)
    r = subprocess.run([sys.executable, "-m", "panel_firewall.firewall", "proxy", "--policy", str(pol), "--key", str(key), "--", "/nonexistent/mcp"],
                       capture_output=True, text=True, input="", timeout=30)
    assert r.returncode == 1 and r.stderr.strip().splitlines()[-1] == "Error: command not found at /nonexistent/mcp" and "Traceback" not in r.stderr


def test_missing_database_key_says_what_to_set():
    assert _reasons({}) == [NO_DB]


def test_unreadable_database_path_names_the_path(tmp_path):
    bad = tmp_path / "nope" / "shop.db"
    (r,) = _reasons({"database": str(bad)})
    assert str(bad) in r and "cannot be opened or read" in r and "OperationalError" not in r


def test_other_counting_failures_keep_the_generic_reason():
    out = sqlguard.analyze("DELETE FROM t WHERE id=1", {}, lambda q: (_ for _ in ()).throw(RuntimeError("boom")))
    assert out.block == ["could not count the affected rows (RuntimeError); blocked for safety"]
