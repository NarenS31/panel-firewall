# Changelog

## Unreleased
- **One-command Panel Cloud setup**: `usepanel init --token pit_... [--cloud-url URL]` (the command the dashboard shows) trades a single-use, 10-minute setup token for a workspace API key and saves it to `~/.config/usepanel/cloud.json` (honours `XDG_CONFIG_HOME`; `PANEL_CONFIG_DIR` overrides; file mode 600, directory 700, written atomically). The key is never printed. `--cloud-url` defaults to `https://app.usepanel.dev`; plain `http://` is refused except for localhost / 127.0.0.1.
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
