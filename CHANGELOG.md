# Changelog

## 0.3.1
- `usepanel demo`: zero-setup interactive demo (no config, no API keys, 5 scenarios)
- README: "Try it in 10 seconds" section, copy-paste configs for Claude Desktop and Cursor
- PyPI keywords expanded for discoverability
- Repo URLs updated to tenthlook org

## 0.3.0
- **Browser sign-in**: `usepanel init --cloud` opens Panel Cloud in your browser, you press Authorize, and the workspace API key is saved for you. No more copying keys.
- **Policy templates** in Panel Cloud: start from E-commerce agent, Support bot or Data analyst instead of a blank policy.
- **Email approval links**: when an action is held, Panel Cloud emails Approve / Deny links (valid for 1 hour, no raw SQL in the message).

## 0.2.0
- **`consent_sql_kinds`** (per-tool, opt-in): statement kinds such as `[delete]` always need a human, even for one row, so a filtered delete is held in Approvals instead of running when it is under `consent_over_rows`. `usepanel init` now writes `consent_sql_kinds: [delete]` for SQL tools. Policies without the key behave exactly as before.
- **One-command Panel Cloud setup**: `usepanel init --token pit_... [--cloud-url URL]` (the command the dashboard shows) trades a single-use, 10-minute setup token for a workspace API key and saves it to `~/.config/usepanel/cloud.json` (honours `XDG_CONFIG_HOME`; `PANEL_CONFIG_DIR` overrides; file mode 600, directory 700, written atomically). The key is never printed. `--cloud-url` defaults to `https://app.usepanel.dev`; plain `http://` is refused except for localhost / 127.0.0.1.
- **Browser setup**: `usepanel init --cloud [--cloud-url URL]` opens `<cloud>/authorize` in your browser, shows a short code to compare with the page, and waits. After you press Authorize it collects the workspace API key and saves it exactly as `--token` does (nothing to copy or paste, key never printed). The URL carries only a request id and the SHA-256 of a verifier that stays in the CLI, so the link alone cannot fetch the key; if no browser can be opened the link is printed. Gives up after 10 minutes.
- `usepanel proxy` and `usepanel serve` with neither `--policy` nor `--cloud-url` use the saved cloud and key, so after setup `usepanel proxy -- <cmd>` is enough. `--api-key`, `--api-key-file` and `PANEL_API_KEY` still win over the saved key, and the saved key is never sent to a different `--cloud-url` than the one that issued it.
- `usepanel doctor` picks up the saved setup, says where the API key came from (flag, environment or saved config) without printing it, and warns if the saved config is readable by other users.
- `usepanel init -- <upstream command>` (starter policy) is unchanged.

## 0.1.1
- **Circuit breaker** (`circuit_breaker:` in the policy): N enforced blocks inside T seconds freeze every tool that is not a read, with a signed receipt. `usepanel unfreeze` lifts it (approval PIN). Off unless the policy enables it; never acts in shadow mode.
- **Per-order duplicate guard** (`duplicate_guard: {field, within_seconds}` per tool): a second executed action with the same order id inside the window is held for a human.
- **`usepanel doctor`**: checks the signing key, PIN, upstream command, API key and cloud reachability and prints the fix for each problem. It never prints the key.
- **`usepanel fingerprint`**: prints the receipt-signing key's fingerprint, the string Panel Cloud shows when you confirm the key.
- **Panel Cloud sync**: events carry the signed receipt (so the cloud can verify it), the proxy reports the names and parameter types of upstream tools (never descriptions or values), and it applies signed unfreeze decisions bound to the exact freeze.
- Approval PIN, shadow mode (`usepanel proxy --shadow`, `usepanel report`) and PII-scrubbed export (`usepanel export-log`) as in the README.
- `tenthlook-core` is on PyPI; the install note about building it from source is gone.

## 0.1.0
First release: action firewall (MCP proxy, deterministic policy, consent, idempotency, signed hash-chained receipts) and the support-bot guard.
