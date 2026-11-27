from panel_firewall.firewall.cli import main


def test_demo_runs_with_no_config(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["demo", "--no-color"]) == 0
    out = capsys.readouterr().out
    for marker in ("[1/5]", "[5/5]", "BLOCKED", "HELD", "FROZEN", "signatures that verify: 8"):
        assert marker in out
    assert "\033[" not in out
    assert not list(tmp_path.rglob("*.key"))      # nothing written to the user's home
