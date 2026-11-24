# Changelog

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
