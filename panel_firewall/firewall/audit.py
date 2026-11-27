"""Read-only, heuristic MCP tool audit. Never invokes tools/call or loads credentials."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys

import yaml

from panel_firewall.firewall.init import classify, tokens, DESTRUCTIVE, PATH_PARAMS, SQL_PARAMS
from panel_firewall.firewall.policy import load_policy
from panel_firewall.firewall.types import FirewallError


@dataclass
class Finding:
    name: str
    severity: str
    reasons: list[str]
    sql_fields: list[str]
    amount_fields: list[str]
    path_fields: list[str]


def fields(schema: dict, prefix: str = "", seen: frozenset = frozenset(), root: dict | None = None) -> list[tuple[str, dict]]:
    """Inspect properties and local schema alternatives/refs, including nested inputs."""
    if not isinstance(schema, dict) or id(schema) in seen:
        return []
    seen = seen | {id(schema)}
    root = schema if root is None else root
    result = []
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        target = root
        for part in ref[2:].split("/"):
            target = target.get(part.replace("~1", "/").replace("~0", "~")) if isinstance(target, dict) else None
        result.extend(fields(target, prefix, seen, root))
    for name, spec in (schema.get("properties") or {}).items():
        if not isinstance(spec, dict):
            continue
        path = f"{prefix}.{name}" if prefix else name
        result.append((path, spec))
        result.extend(fields(spec, path, seen, root))
    for key in ("allOf", "anyOf", "oneOf"):
        for sub in schema.get(key, []):
            result.extend(fields(sub, prefix, seen, root))
    if isinstance(schema.get("items"), dict):
        result.extend(fields(schema["items"], prefix + "[]", seen, root))
    return result


def analyze(tool: dict, policy=None) -> Finding:
    name = tool["name"]
    props = fields(tool.get("inputSchema") or {})
    sql, amounts, paths = [], [], []
    for field, spec in props:
        leaf = field.rsplit(".", 1)[-1].removesuffix("[]")
        parts = set(tokens(leaf))
        desc = str(spec.get("description", "")).lower()
        if leaf.lower() in SQL_PARAMS or "sql" in parts or "sql" in tokens(desc):
            sql.append(field)
        if "amount" in parts or leaf.lower() in {"cents", "price", "total"}:
            amounts.append(field)
        if leaf.lower() in PATH_PARAMS or parts & {"file", "filename", "path", "paths", "directory", "filepath"}:
            paths.append(field)
    rule = policy.rule_for(name) if policy else {}
    # Unlisted actions are default-denied by Panel, not a gap in the policy.
    blocked = policy is not None and (rule is None or rule.get("allowed", True) is not True)
    reasons, severity = [], "clean"
    if blocked:
        reasons.append("blocked by policy (explicitly or default deny)")
    else:
        rule = rule or {}
        if sql and (len(set(sql)) != 1 or rule.get("sql_arg") not in sql):
            reasons.append("SQL input without a matching sql_arg AST guard")
            severity = "high"
        destructive = set(tokens(name + " " + str(tool.get("description", "")))) & DESTRUCTIVE
        if destructive:
            reasons.append("destructive name/description without allowed: false")
            severity = "high"
        if amounts and ("max_amount" not in rule or rule.get("amount_field", "amount") not in amounts or len(set(amounts)) > 1):
            reasons.append("amount input without a matching max_amount cap")
            severity = "high"
        if paths and (not set(paths).issubset(set(rule.get("path_args") or [])) or
                      not (rule.get("allowed_roots") or rule.get("protected"))):
            reasons.append("file/path input without path_args and protected/allowed_roots")
            if severity == "clean":
                severity = "medium"
    return Finding(name, severity, reasons, sorted(set(sql)), sorted(set(amounts)), sorted(set(paths)))


def starter(tools: list[dict], findings: list[Finding]) -> str:
    actions = {}
    for tool, finding in zip(tools, findings):
        c = classify(tool)
        rule = {"risk": c["risk"] if c["risk"] != "unknown" else "write"}
        if c["risk"] in {"unknown", "destructive"} or any("destructive name" in r for r in finding.reasons):
            rule["allowed"] = False
        if finding.sql_fields:
            rule.update(sql_arg=finding.sql_fields[0], sql={}, max_rows=10, consent_sql_kinds=["delete"])
        if finding.amount_fields:
            rule.update(amount_field=finding.amount_fields[0], max_amount=0)
        if finding.path_fields:
            rule.update(path_args=finding.path_fields, allowed_roots=["/CHANGE/ME"],
                        protected={"*": ["*/.env", "*/.ssh/*", "*/.git/*"]})
        # The proxy's argument selectors address top-level fields only. Never suggest
        # a partial guard for nested inputs or multiple independent SQL/amount fields.
        if (any("." in f or "[]" in f for f in finding.sql_fields + finding.amount_fields + finding.path_fields)
                or len(finding.sql_fields) > 1 or len(finding.amount_fields) > 1):
            rule["allowed"] = False
            rule["note"] = "Review complex inputs; blocked until an adapter can guard every sensitive field."
        actions[finding.name] = rule
    if not actions:
        return "# No tools discovered; no actionable starter policy generated.\n"
    return ("# Heuristic starter only: review tool semantics, caps, folders and approval setup.\n"
            "# Set database: ./app.db for SQL row counts; /CHANGE/ME is a placeholder, not a sandbox.\n"
            "# A clean audit means no listed heuristic gap, not a security certification.\n" +
            yaml.safe_dump({"version": "0.1-draft", "reviewed": False, "mode": "approval", "actions": actions}, sort_keys=False))


async def discover(cmd: list[str]) -> list[dict]:
    from panel_firewall.firewall.gateway import McpUpstream

    class Sink:
        async def on_upstream_message(self, up, msg):
            # Discovery does not service sampling/elicitation or execute any tools.
            if isinstance(msg, dict) and "method" in msg and msg.get("id") is not None:
                await up.send({"jsonrpc": "2.0", "id": msg["id"],
                               "error": {"code": -32601, "message": "audit only supports discovery"}})
        async def on_upstream_closed(self, up):
            pass

    up = McpUpstream("audit", cmd, Sink())
    try:
        await up.start()
        reply = await up.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "panel-audit", "version": "0.1"}}, 30)
        if "error" in reply:
            raise FirewallError(f"upstream refused initialize: {reply['error']}")
        await up.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools, cursors, names, cursor = [], set(), set(), None
        while True:
            reply = await up.request("tools/list", {"cursor": cursor} if cursor else {}, 30)
            result = reply.get("result")
            if "error" in reply or not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                raise FirewallError("upstream returned an invalid tools/list response")
            for tool in result["tools"]:
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"] or tool["name"] in names:
                    raise FirewallError("upstream returned an invalid or duplicate tool name")
                if not isinstance(tool.get("inputSchema", {}), dict):
                    raise FirewallError("upstream returned an invalid inputSchema")
                tools.append(tool)
                names.add(tool["name"])
            cursor = result.get("nextCursor")
            if cursor is None:
                return tools
            if not isinstance(cursor, str) or not cursor or cursor in cursors or len(cursors) >= 1000:
                raise FirewallError("upstream returned invalid or repeated tools/list pagination")
            cursors.add(cursor)
    finally:
        await up.stop()


def run_audit(a) -> int:
    cmd = list(a.upstream)
    if cmd and cmd[0] == "--":
        cmd.pop(0)
    if not cmd:
        raise FirewallError("usage: usepanel audit [--policy policy.yaml] [--out policy.yaml] -- <upstream command>")
    if a.out and Path(a.out).exists():
        raise FirewallError(f"{a.out} exists; choose a new --out path")
    try:
        policy = load_policy(a.policy) if a.policy else None
    except OSError as exc:
        raise FirewallError(f"could not read policy: {exc}") from exc
    try:
        tools = asyncio.run(discover(cmd))
    except OSError as exc:
        raise FirewallError(f"could not start upstream: {exc}") from exc
    findings = [analyze(tool, policy) for tool in tools]
    color = not a.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()
    colors = {"high": "31", "medium": "33", "clean": "32"}
    print("Panel tool audit (heuristic; definitions only, no tools invoked)")
    if not policy:
        print("No policy supplied: checking for missing Panel controls, not upstream implementation guards.")
    for f in findings:
        line = f"{f.severity.upper():6} {json.dumps(f.name, ensure_ascii=True)}: {'; '.join(f.reasons) or 'no listed heuristic gaps'}"
        print(f"\033[{colors[f.severity]}m{line}\033[0m" if color else line)
    print(" | ".join(f"{sum(f.severity == level for f in findings)} {level}" for level in colors))
    draft = starter(tools, findings)
    if a.out:
        # Exclusive creation avoids overwriting a file created while discovery ran.
        try:
            with Path(a.out).open("x") as out:
                out.write(draft)
        except OSError as exc:
            raise FirewallError(f"could not write starter policy: {exc}") from exc
        print(f"Starter policy written to {a.out}; review before use.")
    else:
        print("\nStarter policy YAML:\n" + draft)
    return 0
