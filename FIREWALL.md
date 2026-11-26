# Panel action firewall: quickstart

Panel sits between an AI agent and its tools. Every tool call goes **intercept → verify → consent → execute (once) → log → receipt**.
The allow / needs_consent / block decision is plain deterministic code reading your YAML policy and the ledger. No model is
consulted when deciding.

## Install

```bash
cd products/panel
python3.11 -m venv .venv && .venv/bin/pip install -e . pytest numpy
.venv/bin/usepanel keygen          # Ed25519 receipt key -> ~/.config/panel/receipt_ed25519.pem (mode 600, refused inside a git repo)
```
Panel **refuses to start without that key**. There is no default secret.

## Wrap an existing MCP server with no code changes

```bash
# 1. let Panel inspect the server and write a starter policy
.venv/bin/usepanel init --out policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /srv/data
# 2. REVIEW policy.yaml (it is a heuristic: reads allowed, writes need approval, destructive/unknown blocked, money caps = 0)
# 3. run the proxy; point your MCP client at this command instead of at the server
.venv/bin/usepanel proxy --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /srv/data
```

**Claude Code / any MCP client**: use `examples/mcp.json` (stdio `command` + `args`), or
`claude mcp add fs-via-panel -- /ABS/.venv/bin/usepanel proxy --policy /ABS/policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /srv/data`.

## Serve Panel's own connectors (SQLite, Stripe test mode, Shopify)

```bash
.venv/bin/usepanel serve --policy examples/policy.native.yaml     # tools: sql_query, stripe_refund, stripe_customer_credit
```

## Try it first: shadow mode

```bash
.venv/bin/usepanel proxy --shadow --policy policy.yaml -- <your server>     # or `mode: shadow` in the policy
.venv/bin/usepanel report --since 48h                                        # what would have been blocked / held, by rule
.venv/bin/usepanel export-log --out log.jsonl --since 48h                    # PII-scrubbed summaries; add --include-raw-args only if you must
```
Shadow mode evaluates every call, **lets it run**, and logs `would have blocked` / `would have asked` (events named `shadow`; receipts
carry `mode=shadow` and `shadow_would=...`). It evaluates against `enforce_mode` (`approval` by default, so every non-read call shows up as
"would have asked"; set `enforce_mode: auto` in the policy to see only the policy's own rules). The agent is not told what would have
happened. Panel never switches to enforcing by itself: you remove `--shadow`. Start here for 48 hours, read the report, then enforce.

PII scrubbing masks emails, phone numbers, card-like numbers and API-key-like strings in summaries, the report and `export-log`;
receipt hashes are left alone. It is pattern matching, not a guarantee, so raw arguments are never exported without `--include-raw-args`.
`export-receipts --scrub` writes a masked copy that no longer verifies (keep the signed original for audits).

## Approving held actions (out-of-band only)

A call the policy marks `needs_consent` is **held**: it is not executed and the agent is told an approval id. Consent can only
come from a channel the agent's tool calls cannot reach, **and it needs your approval PIN**:

```bash
.venv/bin/usepanel pin set                                          # once; typed at the terminal, only a salted hash is stored
.venv/bin/usepanel pending --policy policy.yaml
.venv/bin/usepanel approve <id> --policy policy.yaml --who alice     # prompts for the PIN on /dev/tty; `usepanel deny <id>` needs none
.venv/bin/usepanel ui --policy policy.yaml                           # http://127.0.0.1:8765/?t=<token>, localhost only; Approve asks for the PIN
```
After approval the agent repeats the same call and it runs **once**. Fields like `consent: true` or `_meta` in the agent's
call are ignored (tested). Who and when are recorded in the ledger, with proof that a PIN-backed, single-use token was used.
`approve` refuses when stdin/stdout are not a terminal, when there is no controlling terminal, when no PIN is set, and during a
lockout (5 wrong PINs: 5 minutes, doubling to 1 hour). See "Security model" in the README for what this does and does not stop.

**Limit:** the PIN does not stop an agent that has full access as your OS user (it can edit the PIN file or the ledger). Run agents
that have a shell under a separate OS user or sandbox, or approve from another device.

## Policy file

See `examples/` and the docstring at the top of `panel_firewall/firewall/policy.py` (rule keys: `allowed`, `risk`, `required_fields`,
`amount_field`, `max_amount`, `consent_over_amount`, `max_rows`, `consent_over_rows`, `protected`, `consent_if`, `block_if`,
`rate_limit`, `max_total_amount`, `duplicate_guard`, `sql_arg`, `path_args`, `allowed_roots`). Typos in rule keys are errors, not silent no-ops.

> **SQL limit:** the guard blocks `UPDATE`/`DELETE` with no `WHERE` or a constant-true one (`WHERE 1=1`), but it does not detect a tautology mixed with a column (`WHERE id=1 OR 1=1`). The row count is what stops it, so give every SQL tool that can write a `max_rows` or `consent_over_rows` (or `consent_sql_kinds`). See KNOWN_ISSUES.md.
Unlisted tools are blocked. Modes: `dry_run` (nothing executes), `approval` (every non-read action needs a human), `auto`, `shadow` (log only, nothing enforced).

### Per-order duplicate guard
`duplicate_guard: {field: order_id, within_seconds: 604800}` on a tool: a second action with the same `order_id` that EXECUTED inside the window is held for a
human (`needs_consent`), so a refund on an order that already had one needs approval. A missing `order_id` blocks. It complements, and does not replace, the
built-in idempotency: running the exact same action twice only ever executes once.

### Circuit breaker
`circuit_breaker: {blocks: 3, per_seconds: 60}` (top level; `{}` means those defaults; absent means off; never acts in shadow mode). When that many enforced
blocks happen inside the window, every tool that is not a read is frozen and a signed receipt (`outcome=frozen`) is written. A human lifts it with
`usepanel unfreeze` (approval PIN, typed on the terminal) or, with Panel Cloud, with a signed unfreeze decision bound to that exact freeze. A human's own
denial and the blocks caused by the freeze itself do not count toward tripping it.

## Receipts

Each executed or blocked action gets a signed receipt in the ledger. `usepanel export-receipts --out r.json`, then
`usepanel verify-receipt one.json --pubkey ~/.config/panel/receipt_ed25519.pem.pub --policy policy.yaml`.
A receipt proves **what Panel checked and decided** and that the record **was not altered**. It is **not** a proof the action was safe.

## Idempotency

Key = the explicit `_meta["panel/idempotency_key"]` if the client sends one, else `sha256(session + tool + arguments)`.
The same key never executes twice; a repeat returns the recorded result. Only a successful upstream call is recorded as executed;
failed calls can be retried; a timeout (outcome unknown) is **not** retried automatically. Read tools (`risk: read`) are never deduplicated.
Consequence to know about: an *intentionally* repeated identical write in one session looks like a retry. Give such calls different
idempotency keys.
