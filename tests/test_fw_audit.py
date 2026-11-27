"""Discovery audits work without keys/PINs and never call upstream tools."""
import asyncio
import json
from pathlib import Path
import sys

import pytest
import yaml

from panel_firewall.firewall.audit import analyze, discover, starter
from panel_firewall.firewall.cli import main
from panel_firewall.firewall.policy import parse_policy
from panel_firewall.firewall.types import FirewallError


def tool(name="inspect", description="", **props):
    return {"name": name, "description": description, "inputSchema": {"type": "object", "properties": props}}


@pytest.mark.parametrize("definition,severity,reason", [
    (tool("query_db", query={"type": "string"}), "high", "SQL"),
    (tool("inspect", "Can remove a record"), "high", "destructive"),
    (tool("dropTable"), "high", "destructive"),
    (tool("refund", amount_usd={"type": "number"}), "high", "max_amount"),
    (tool("read_file", path={"type": "string"}), "medium", "allowed_roots"),
    (tool("list_products"), "clean", ""),
])
def test_findings(definition, severity, reason):
    result = analyze(definition)
    assert result.severity == severity
    assert reason in ";".join(result.reasons)


def test_policy_guards_must_match_actual_inputs():
    policy = parse_policy({"actions": {
        "query_db": {"sql": {}, "sql_arg": "wrong"},
        "refund": {"max_amount": 0, "amount_field": "amount_usd"},
        "read_file": {"path_args": ["path"], "allowed_roots": ["/data"]},
        "delete": {"allowed": False},
    }})
    assert analyze(tool("query_db", query={}), policy).severity == "high"
    policy.actions["query_db"]["sql_arg"] = "query"
    assert analyze(tool("query_db", query={}), policy).severity == "clean"
    assert analyze(tool("refund", amount_usd={}), policy).severity == "clean"
    assert analyze(tool("read_file", path={}), policy).severity == "clean"
    assert analyze(tool("delete"), policy).severity == "clean"
    assert analyze(tool("unlisted", amount={}), policy).severity == "clean"
    policy.actions["read_file"].pop("path_args")
    assert analyze(tool("read_file", path={}), policy).severity == "medium"


def test_starter_is_valid_and_blocks_complex_inputs():
    tools = [tool("refund", amount={}), tool("inspect", "remove records", query={}),
             tool("read_file", path={}), tool("unknown", request={"properties": {"amount": {"type": "number"}}})]
    draft = yaml.safe_load(starter(tools, [analyze(t) for t in tools]))
    policy = parse_policy(draft)
    assert draft["reviewed"] is False and draft["mode"] == "approval"
    assert policy.actions["refund"]["max_amount"] == 0
    assert policy.actions["inspect"]["allowed"] is False
    assert policy.actions["inspect"]["sql_arg"] == "query"
    assert policy.actions["read_file"]["allowed_roots"] == ["/CHANGE/ME"]
    assert policy.actions["unknown"]["allowed"] is False


def fake_server(tmp_path, mode="normal"):
    script = tmp_path / "upstream.py"
    log = tmp_path / "calls.jsonl"
    script.write_text('''import sys,json
mode = ''' + repr(mode) + '''
for line in sys.stdin:
 m=json.loads(line)
 with open(''' + repr(str(log)) + ''',"a") as f: f.write(json.dumps(m)+"\\n")
 if "id" not in m: continue
 method=m["method"]
 if method=="initialize": result={"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}
 elif mode=="error":
  print(json.dumps({"jsonrpc":"2.0","id":m["id"],"error":{"code":-32603,"message":"broken"}}),flush=True);continue
 else:
  second=bool(m.get("params",{}).get("cursor"))
  result={"tools":[{"name":"list_items" if second else "refund","inputSchema":{"properties":{} if second else {"amount":{"type":"number"}}}}]}
  if mode=="cycle" or not second: result["nextCursor"]="next"
 print(json.dumps({"jsonrpc":"2.0","id":m["id"],"result":result}),flush=True)
''')
    return [sys.executable, str(script)], log


def test_zero_config_cli_and_output_file(tmp_path, monkeypatch, capsys):
    cmd, log = fake_server(tmp_path)
    assert main(["audit", "--no-color", "--", *cmd]) == 0
    text = capsys.readouterr().out
    assert "HIGH" in text and "CLEAN" in text and "max_amount: 0" in text
    assert "\033[" not in text
    messages = [json.loads(line) for line in log.read_text().splitlines()]
    assert {m["method"] for m in messages} == {"initialize", "notifications/initialized", "tools/list"}
    assert not list(tmp_path.glob("*.pem"))
    out = tmp_path / "policy.yaml"
    assert main(["audit", "--out", str(out), "--", *cmd]) == 0
    parse_policy(yaml.safe_load(out.read_text()))
    original = out.read_text()
    assert main(["audit", "--out", str(out), "--", *cmd]) == 2
    assert out.read_text() == original


@pytest.mark.parametrize("mode", ["error", "cycle"])
def test_discovery_errors_never_report_clean(tmp_path, mode):
    cmd, _ = fake_server(tmp_path, mode)
    with pytest.raises(FirewallError):
        asyncio.run(discover(cmd))


def test_missing_command_and_cli_usage(capsys):
    assert main(["audit"]) == 2
    assert main(["audit", "--", "/nonexistent/panel-audit-test"]) == 1


def test_report_colors(tmp_path, monkeypatch, capsys):
    cmd, _ = fake_server(tmp_path)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert main(["audit", "--", *cmd]) == 0
    report = capsys.readouterr().out
    assert "\033[31mHIGH" in report and "\033[32mCLEAN" in report


def test_local_refs_and_recursive_inputs_are_bounded():
    definition = tool("inspect")
    definition["inputSchema"].update({
        "$defs": {"input": {"properties": {"amount": {"type": "number"}, "again": {"$ref": "#/$defs/input"}}}},
        "properties": {"request": {"$ref": "#/$defs/input"}},
    })
    finding = analyze(definition)
    assert finding.amount_fields == ["request.amount"]
    assert finding.severity == "high"
    policy = parse_policy(yaml.safe_load(starter([definition], [finding])))
    assert policy.actions["inspect"]["allowed"] is False
