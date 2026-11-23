"""`usepanel doctor`: check the things that stop a proxy from working and print the exact fix for each. Read-only: it changes nothing,
sends no event, and prints no secret (the API key is shown only as its first 8 characters)."""
from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx

OK, WARN, FAIL = "ok", "warn", "fail"


@dataclass
class Check:
    status: str
    name: str
    detail: str
    fix: str = ""


def _api_key(a) -> str | None:
    key = getattr(a, "api_key", None) or os.environ.get("PANEL_API_KEY")
    kf = getattr(a, "api_key_file", None)
    if not key and kf:
        try:
            key = Path(kf).expanduser().read_text().strip()
        except OSError:
            return None
    return key or None


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

    url = getattr(a, "cloud_url", None)
    if not url:
        pol = getattr(a, "policy", None)
        if pol:
            add(OK if Path(pol).expanduser().is_file() else FAIL, "Local policy file", pol, "" if Path(pol).expanduser().is_file() else "Create one with `usepanel init --out policy.yaml -- <upstream command>`.")
        else:
            add(WARN, "Policy", "no --policy and no --cloud-url given", "Pass `--policy policy.yaml`, or `--cloud-url https://app.usepanel.dev --api-key-file key.txt`.")
        return out

    key = _api_key(a)
    if not key:
        add(FAIL, "Panel Cloud API key", "none given", "Pass --api-key-file FILE (best), or set PANEL_API_KEY. Create a key in the dashboard under the workspace's API keys tab.")
        return out
    if not key.startswith("pcl_"):
        add(FAIL, "Panel Cloud API key", f"{key[:4]}… does not look like a Panel key (they start with pcl_)", "Copy the key again from the dashboard; it is shown only once, so create a new one if it is lost.")
        return out
    add(OK, "Panel Cloud API key", f"{key[:8]}… (looks right)")

    try:
        with httpx.Client(base_url=url.rstrip("/"), headers={"Authorization": f"Bearer {key}"}, timeout=8, transport=transport, follow_redirects=False) as c:
            r = c.get("/v1/proxy/ping")
    except httpx.HTTPError as e:
        add(FAIL, "Panel Cloud reachable", f"{url}: {type(e).__name__}", "Check the URL and your network. Enforcement keeps working offline from the last cached signed policy, and actions that need approval stay held.")
        return out
    if r.status_code in (401, 403):
        add(FAIL, "Panel Cloud API key accepted", f"rejected (HTTP {r.status_code})", "The key is wrong or was revoked. Create a new key in the dashboard.")
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
