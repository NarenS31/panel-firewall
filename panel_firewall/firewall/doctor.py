"""`usepanel doctor`: check the things that stop a proxy from working and print the exact fix for each. Read-only: it changes nothing,
sends no event, and prints no secret (the API key is shown only as its first 8 characters, with where it came from: a flag,
PANEL_API_KEY, or the config saved by `usepanel init --token`)."""
from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx

from panel_firewall.firewall.types import FirewallError

OK, WARN, FAIL = "ok", "warn", "fail"


@dataclass
class Check:
    status: str
    name: str
    detail: str
    fix: str = ""


def run_checks(a, transport=None) -> list[Check]:
    out: list[Check] = []
    add = lambda s, n, d, f="": out.append(Check(s, n, d, f))

    v = sys.version_info
    add(OK if v >= (3, 11) else FAIL, "Python", f"{v.major}.{v.minor}.{v.micro}", "" if v >= (3, 11) else "Install Python 3.11 or newer.")

    try:
        from panel_firewall.firewall.receipts import Signer
        s = Signer.load(getattr(a, "key", None))
        add(OK, "Receipt signing key", f"found ({s.path})")
    except Exception as e:
        add(FAIL, "Receipt signing key", str(e).split(". ")[0], "Run `usepanel keygen`. Panel will not start without a key.")

    try:
        from panel_firewall.firewall.pin import PinStore
        st = PinStore(getattr(a, "pin_file", None)).status()
        if not st["set"]:
            add(WARN, "Approval PIN", "not set: approving a held action is refused until one exists", "Run `usepanel pin set` in a terminal.")
        elif st.get("locked_for", 0) > 0:
            add(WARN, "Approval PIN", f"set, but locked for {int(st['locked_for'])}s after wrong attempts", "Wait for the lockout to end.")
        else:
            add(OK, "Approval PIN", "set")
    except Exception as e:
        add(WARN, "Approval PIN", f"could not check ({type(e).__name__})", "Run `usepanel pin status`.")

    up = [x for x in (getattr(a, "upstream", None) or []) if x != "--"]
    if up:
        found = shutil.which(up[0])
        add(OK if found else FAIL, "Upstream command", f"{up[0]} " + ("found" if found else "not found on PATH"),
            "" if found else f"Install `{up[0]}` or give the full path after `--`.")

    from panel_firewall.firewall.cloud import (
        config_path,
        load_saved_config,
        resolve_api_key,
        saved_config_mismatch,
    )
    init_fix = "Run the `usepanel init --token ...` command shown in the Panel Cloud dashboard again (it makes a new key)."
    url = getattr(a, "cloud_url", None)
    saved = None
    if not url and not getattr(a, "policy", None):
        try:
            saved = load_saved_config()
        except FirewallError as e:
            add(FAIL, "Saved Panel Cloud setup", str(e), init_fix)
            return out
        if saved:
            url = saved["cloud_url"]
            ws = saved.get("workspace_name") or saved.get("workspace_id") or "?"
            add(OK, "Saved Panel Cloud setup", f"workspace {ws} at {url} ({config_path()})")
            try:
                mode = config_path().stat().st_mode & 0o777
            except OSError:
                mode = 0o600
            if mode & 0o077:
                add(WARN, "Saved config permissions", f"{config_path()} is mode {mode:o}: other users may read the API key",
                    f"Run `chmod 600 {config_path()}`.")
    if not url:
        pol = getattr(a, "policy", None)
        if pol:
            add(OK if Path(pol).expanduser().is_file() else FAIL, "Local policy file", pol, "" if Path(pol).expanduser().is_file() else "Create one with `usepanel init --out policy.yaml -- <upstream command>`.")
        else:
            add(WARN, "Policy", "no --policy, no --cloud-url and no saved Panel Cloud setup",
                "Run the `usepanel init --token ...` command from the Panel Cloud dashboard, or pass `--policy policy.yaml`.")
        return out

    try:
        key, src = resolve_api_key(a, url)
    except FirewallError as e:
        add(FAIL, "Panel Cloud API key", str(e), "Fix the path, or drop the flag to use the saved setup.")
        return out
    if not key:
        add(FAIL, "Panel Cloud API key", (f"{src} is empty" if src else "none given") + saved_config_mismatch(url),
            "Run the `usepanel init --token ...` command from the dashboard (best), or pass --api-key-file FILE, or set PANEL_API_KEY.")
        return out
    if not key.startswith("pcl_"):
        add(FAIL, "Panel Cloud API key", f"{key[:4]}… from {src} does not look like a Panel key (they start with pcl_)", "Copy the key again from the dashboard; it is shown only once, so create a new one if it is lost.")
        return out
    add(OK, "Panel Cloud API key", f"{key[:8]}… from {src} (looks right)")

    try:
        with httpx.Client(base_url=url.rstrip("/"), headers={"Authorization": f"Bearer {key}"}, timeout=8, transport=transport, follow_redirects=False) as c:
            r = c.get("/v1/proxy/ping")
    except httpx.HTTPError as e:
        add(FAIL, "Panel Cloud reachable", f"{url}: {type(e).__name__}", "Check the URL and your network. Enforcement keeps working offline from the last cached signed policy, and actions that need approval stay held.")
        return out
    if r.status_code in (401, 403):
        add(FAIL, "Panel Cloud API key accepted", f"rejected (HTTP {r.status_code})", "The key is wrong or was revoked. " +
            (init_fix if src.startswith("saved config") else "Create a new key in the dashboard."))
        return out
    if r.status_code >= 400:
        add(FAIL, "Panel Cloud reachable", f"HTTP {r.status_code}", "Check the --cloud-url. It should be the API origin, for example https://app.usepanel.dev.")
        return out
    j = r.json()
    add(OK, "Panel Cloud reachable", f"workspace {j.get('workspace_id')}, mode {j.get('mode')}, policy v{j.get('policy_version')}")
    if j.get("mode") == "shadow":
        add(OK, "Mode", "shadow: actions run, and Panel records what it WOULD have blocked. Turn on enforcement in the dashboard when ready.")

    try:
        from panel_firewall.firewall.cloud import CloudState
        pin = CloudState(url, key, getattr(a, "cloud_state_dir", None)).pinned()
        if pin:
            add(OK, "Pinned cloud signing key", f"{pin['public_key'][:12]}… for workspace {pin['workspace_id']}")
        else:
            add(WARN, "Pinned cloud signing key", "none yet: the first `usepanel proxy` run pins it", "Pass --cloud-pubkey with the key shown at <cloud-url>/v1/proxy/policy-key to pin it ahead of time.")
    except Exception:
        pass
    return out


def render(checks: list[Check]) -> str:
    mark = {OK: "ok  ", WARN: "warn", FAIL: "FAIL"}
    lines = []
    for c in checks:
        lines.append(f"[{mark[c.status]}] {c.name}: {c.detail}")
        if c.fix and c.status != OK:
            lines.append(f"       fix: {c.fix}")
    bad = sum(c.status == FAIL for c in checks)
    lines.append("")
    lines.append("Everything needed is in place." if not bad and not any(c.status == WARN for c in checks)
                 else f"{bad} problem(s) to fix." if bad else "No blocking problems; see the warnings above.")
    return "\n".join(lines)


def cmd_doctor(a) -> int:
    checks = run_checks(a)
    print(render(checks))
    return 1 if any(c.status == FAIL for c in checks) else 0
