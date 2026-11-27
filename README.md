# Panel: checks what an agent says and what it does

An agent can go wrong in two ways: it **does** something it should not (a refund over the limit, a `DELETE` without a `WHERE`, the same charge twice), or it **says** something that is not true ("I've refunded you" when nothing was refunded).
Panel is two layers that check both, with deterministic code and **no model in any verdict**.

| Layer | Checks | Sits between | Start here |
|---|---|---|---|
| **Action firewall** (`panel_firewall.firewall`) | what an agent *does*: tool calls to Stripe (test mode), Shopify dev stores, SQLite, or any MCP server | agent and tools (an MCP proxy) | [FIREWALL.md](FIREWALL.md) |
| **Support guard** (`panel_firewall.guard`) | what a support bot *says and does* to a customer: promises vs. a written policy, actions only with consent | bot and customer (an OpenAI-compatible proxy) | [GUARD_README.md](GUARD_README.md) |

Both are **early, single-author, sandbox-only** software. Read "Limits" before relying on any number below.

## How the firewall works
```
agent ──tool call──▶ Panel ──▶ policy check (code over a YAML policy and an append-only ledger) ──▶ allow / needs_consent / block
                       │            ├─ block: reasons go back to the agent; nothing runs
                       │            ├─ needs_consent: held until a human approves OUT OF BAND (usepanel approve, local UI)
                       │            └─ allow: claim the idempotency key ▶ execute once ▶ ledger ▶ signed receipt
                       └─ before a reply reaches a person: "it's done" claims must cite a receipt the ledger confirms, else the reply is rewritten
```
Fail closed (unknown tool, bad argument, engine error: block). Consent never comes from the agent's own arguments. SQL is parsed to an AST (sqlglot): single statement, allowlisted kinds, protected tables, row-count caps, a SQLite authorizer as a second layer. Receipts are Ed25519-signed and hash-chained ([tenthlook-core](https://pypi.org/project/tenthlook-core/) format).

## How the guard works
The support guard parses the bot's reply into promises and actions, checks them against a written store policy (refund window, amount limits, escalation threshold, discount cap) and the real order record, and lets a reply through only if every promise is backed.
**v7 (new) consent:** before any action runs, Panel sends a confirmation question it generates from the action ("To confirm: refund $24.00 on order #1042? Reply yes to proceed."), and only a short plain yes to *that* message counts; anything else is re-asked once, then handed to a person (`panel_firewall/guard/v7.py`, [results/v7_report.md](results/v7_report.md)). Earlier versions (v6.x) read the customer's words with phrase rules and are kept frozen.

## Try it in 10 seconds
No config, no API keys, nothing to set up:
```bash
pipx run panel-firewall demo
```
Runs a simulated support agent that tries five actions — a lookup, a small refund, an over-limit refund, one that needs human approval, and a destructive delete — and shows Panel blocking, holding, and approving each one live in your terminal.

## Install and quickstart
Requires Python 3.11+. `tenthlook-core` (the receipt format) is installed automatically.
**With Panel Cloud (one command, no key to copy).** The dashboard shows a setup command with a one-time token (it works once, for 10 minutes). Paste it:
```bash
pip install panel-firewall
usepanel keygen                            # once per machine: the receipt-signing key (outside any git repo, mode 0600)
usepanel init --token pit_... --cloud-url https://app.usepanel.dev    # the command from the dashboard: fetches and saves the workspace API key
usepanel proxy -- npx -y @modelcontextprotocol/server-filesystem /srv/data   # uses the saved cloud and key; point your MCP client at this command
usepanel doctor                            # checks the setup and says where the key came from (never prints it)
```
The key is saved to `~/.config/usepanel/cloud.json` (`$XDG_CONFIG_HOME/usepanel/` if set, or `$PANEL_CONFIG_DIR`), mode 0600 in a 0700 directory, and is never printed. Running a new setup command replaces it.
*Manual alternative:* create a key in the dashboard and pass `--cloud-url https://app.usepanel.dev --api-key-file key.txt`, or set `PANEL_API_KEY`. `--api-key`, `--api-key-file` and `PANEL_API_KEY` always override the saved key, and the saved key is only ever sent to the cloud URL it was issued for.

**Local policy only (no cloud):**
```bash
pip install panel-firewall
usepanel keygen                            # Panel will not start without a signing key (stored outside any git repo, mode 0600)
usepanel pin set                           # your approval PIN, typed at the terminal (see "Security model"); approvals are refused without one
usepanel init --out policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /srv/data     # drafts a starter policy: REVIEW IT

# Start in shadow mode for 48 hours, review the report, then turn on enforcement.
usepanel proxy --shadow --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /srv/data   # point your MCP client at this command
usepanel report --since 48h                # plain summary: what WOULD have been blocked or held, by rule. Nothing was stopped.
usepanel proxy --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /srv/data            # enforcement: you remove --shadow, Panel never does

usepanel pending ; usepanel approve <id>        # approve held actions at the terminal with your PIN (or: usepanel ui)
usepanel doctor                            # checks your setup (key, PIN, upstream, API key, cloud) and prints the fix for each problem
usepanel fingerprint                       # your receipt-signing key's fingerprint (Panel Cloud asks you to confirm it)
usepanel unfreeze                          # lift a circuit-breaker freeze (needs the PIN)
python -m panel_firewall.guard.proxy --upstream https://api.openai.com/v1 --policy my_policy.toml   # the support guard (see GUARD_README.md)
```
**Shadow mode** evaluates every call against your policy, lets it run, and records "would have blocked" / "would have asked" in the ledger (receipts carry `mode=shadow`). It never switches itself to enforcing; you do that by dropping `--shadow` (or `mode: shadow` in the policy). Until then Panel protects nothing, and the proxy says so on start-up. `usepanel report --since 48h` groups the would-be decisions by tool and rule; `usepanel export-log` writes PII-scrubbed summaries (no raw arguments unless you pass `--include-raw-args`).

Example policies and MCP client config: [examples/](examples/). Tests: `pip install -e ".[dev]" && pytest` (the real-MCP-server tests skip if the servers are not installed).

## Copy-paste configs for popular tools

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows):
```json
{
  "mcpServers": {
    "sqlite-via-panel": {
      "command": "usepanel",
      "args": ["proxy", "--policy", "panel-policy.yaml", "--shadow", "--",
               "npx", "-y", "@modelcontextprotocol/server-sqlite", "mydb.sqlite"]
    }
  }
}
```

**Cursor** (`.cursor/mcp.json` in your project):
```json
{
  "mcpServers": {
    "filesystem-via-panel": {
      "command": "usepanel",
      "args": ["proxy", "--policy", "panel-policy.yaml", "--shadow", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}
```

**Any stdio MCP client** — Panel wraps any MCP server command:
```bash
usepanel proxy --policy panel-policy.yaml --shadow -- <your-mcp-server-command>
```
Start with `--shadow` to log what Panel would do without blocking anything. Review with `usepanel report`, then drop `--shadow` to enforce.

## Real results
Every number below is from a file in this repo. Each evaluation was written down and hashed **before** it was run (`*prereg*` files and `FROZEN_*.sha256`). I wrote the policies, tasks, labels and code, so read these as engineering evidence, not independent validation.

**1. Firewall, scripted agent** (47 tasks / 55 calls, sandbox backends; [results/report.md](results/report.md)). A scripted replay, not a model: it shows policy coverage.

| | without Panel | with Panel |
|---|---|---|
| unsafe actions executed (23 should-block calls) | 20 | **0** |
| executed without consent (10 needs-consent calls) | 10 | **0** |
| duplicate executions | 3 | **0** |
| allowed calls completed | 19 / 19 | 19 / 19 |

Latency (Apple M4, loaded machine): policy `validate` median 0.01 ms (Shopify/Stripe), 0.21 ms (SQLite); full `Firewall.handle` with ledger write and signature median 0.36 ms, p95 0.61 ms ([results/eval/latency.json](results/eval/latency.json)).

**2. Firewall, real models** (gpt-4.1 and gpt-4.1-mini, 5 samples x 47 tasks, with and without Panel; [results/llm_report.md](results/llm_report.md)). Without Panel the models executed a should-block action in 67 (gpt-4.1) and 57 (mini) of 115 task-runs and a needs-consent action with no human in 39 and 30 of 45; with Panel, 5 and 11 and **0 and 0**. The 5 and 11 are scoring artifacts that I checked row by row (narrow `DELETE ... WHERE id = 7`-style statements the policy allows). Both models' replies were mostly honest about errors and blocks; the claim blocker had little real to catch and wrongly replaced 24 of 470 honest replies (5.1%) in v1.

**3. Claim blocker** ([results/claims_v2_report.md](results/claims_v2_report.md), [results/llm_cite_report.md](results/llm_cite_report.md)). Replies that say an action happened must cite a receipt id. On a new held-out set (v2): 1 of 124 honest replies wrongly rewritten, 80 of 85 false claims caught, 12 of 12 citation attacks caught. **Models do not cite on their own:** gpt-4.1-mini cited a valid receipt in 37 of 43 replies when the tool result told it to, and in 0 of 43 when the id was visible but the instruction was not. Panel injects the instruction into tool results. Open defects: [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

**4. Support guard, fresh8** (gpt-5.6-luna, 20 conversations, 60 turns per condition, v6.5; [GUARD_README.md](GUARD_README.md), `guard_results/fresh8_compare/`):

| | plain prompt | Panel prompt, no guard | Panel v6.5 |
|---|---|---|---|
| allowed requests carried out | 0 / 10 | 10 / 10 | 9 / 10 |
| unbacked claims in sent replies | 6 / 60 | 0 / 60 | 0 / 60 |
| actions without consent | n/a (executes nothing) | 0 / 60 | 1 / 60 |

**5. Support guard v7, fresh9** (new held-out set, same model; [results/v7_report.md](results/v7_report.md)): 11 of 11 allowed requests carried out, 0 actions without consent, **one extra customer turn per carried-out request** (the yes). The live runs barely tested the yes/not-yes boundary (2 non-yes events on fresh9, none on fresh6/7/8); that boundary is tested by 108 phrase cases in `tests/test_v7.py`.

## Security model
**Approval PIN (anti self-approval).** Held actions are released only by a human. `usepanel approve <id>` and the local UI's Approve button both need an approval PIN that you set once with `usepanel pin set`.
- The PIN is typed on the controlling terminal (`/dev/tty`) only: not an argument, not stdin, not an environment variable. Only a salted scrypt hash is stored (`~/.config/panel/approval_pin.json`, mode 600, outside the repo).
- `usepanel approve` refuses unless stdin, stdout and `/dev/tty` are the same interactive terminal. A background process with piped stdio, or none, is refused. The UI asks for the PIN in a form; wrong attempts are rate-limited with a lockout (5 wrong in a row: 5 minutes, doubling up to 1 hour, kept on disk so a restart does not reset it).
- A correct PIN mints a token bound to that exact pending action (approval id + action hash), valid 60 seconds, usable once. The ledger refuses an approval without a valid token and records the token's nonce, so a replay or a token for another action is refused. Denying never needs the PIN.

*What this blocks:* an agent (or a prompt-injected tool) that runs `usepanel approve <id>`, or `curl`s your running UI's approve endpoint, without your PIN; guessing the PIN online.
*What it does not block:* an agent that can read your keystrokes or screen (a keylogger, a screen-capture tool, a terminal it can inject into); a human who shares the PIN or approves everything without reading; anything with full access as your OS user, which can still rewrite the PIN file or the ledger directly, or start its own UI with its own PIN file. The ledger is a local file, so the PIN raises the bar, it is not a boundary against a determined same-user process.
*Strongest setup:* approve from another device (a second machine or phone that holds the PIN), or run the agent as a separate OS user or container that cannot read the PIN file, the ledger or the signing key.

## Limits
- **Consent is protected by a PIN and the OS user, not a hardware boundary.** The approval PIN stops an agent from running `usepanel approve` or calling the UI without it, but an agent with a shell as the same OS user can still edit the ledger or the PIN file. See "Security model". Stronger: run the agent as a separate OS user or container, or approve from another device.
- **Only guards what is routed through it.** An agent with another path (shell, second MCP server, browser) bypasses Panel.
- **The claim blocker is keyword-based and English-only**; it misses idioms ("dealt with", "pushed it through") and does not check counts. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md).
- **Sandbox only.** Stripe refuses non-`sk_test_` keys; Shopify is for development stores; the Stripe connector has only run against a mock transport, the Shopify connector against fakes (plus one recorded dev-store refund for the older executor).
- **Small, same-author evidence.** One or two models, 20-conversation sets, labels made by an AI agent (second labels from another AI, no human), customers simulated by scripts. "0 in 60" has an upper 95% bound of about 5%.
- **No formal verification.** A receipt proves what Panel checked and that the record was not altered, not that the action was a good idea.
- Not reviewed for production finance, healthcare or other regulated use.

## Repository layout
`panel_firewall/firewall/` firewall engine, connectors, gateway, receipts, claim blocker · `panel_firewall/guard/` support guard (v6.x frozen; v7) · `panel_firewall/execute/` executor and approval page · `eval/` and `results/` firewall evaluations (pre-registrations, hashes, raw rows) · `guard_data/`, `guard_results/` guard sets and runs (fictional store and orders) · `tests/`.

## Get help
Need help setting up Panel on your MCP server? Email narensara@usepanel.dev or open an issue.

License: MIT (see LICENSE).
