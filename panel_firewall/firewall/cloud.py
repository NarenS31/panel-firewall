"""Panel Cloud client for `usepanel proxy --cloud-url ... --api-key ...`.

What the cloud does for a proxy, and what the proxy refuses to trust:
  * POLICY: downloaded as a signed bundle (Ed25519 over an envelope string; the envelope carries the SHA-256 of the exact policy
    text). The proxy verifies the signature against a PINNED public key (trust on first use, or `--cloud-pubkey`), the workspace id,
    the hash, that the version never goes backwards, and that the engine accepts the policy. The verified bytes are cached on disk
    (mode 600) and RE-VERIFIED every time they are loaded, so editing the cache does nothing. If the cloud is down the proxy keeps
    enforcing the cached policy; with no cached policy it refuses to start.
  * EVENTS: one record per signed receipt, data-minimised (tool, verdict, rule, amount, plain summary, receipt/action/policy hashes).
    Raw arguments never leave the machine. Uploads are at-least-once from the local ledger (a cursor), de-duplicated by the cloud.
  * APPROVALS: a held action is registered with the cloud; a decision made there comes back as a signed message that is accepted only
    if the signature, workspace, approval id, exact action hash, expiry and single-use nonce all check out. Offline, held actions simply
    stay held: nothing is ever approved by default.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from panel_firewall.firewall.policy import Policy, load_policy
from panel_firewall.firewall.types import FirewallError, sha256_hex

log = logging.getLogger("panel.cloud")
STATE_ROOT = "~/.config/panel/cloud"
_VERDICT = {"ALLOWED": "allow", "NEEDS_CONSENT": "needs_consent", "BLOCKED": "block"}


class CloudError(FirewallError):
    pass


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def verify_signature(pubkey_b64: str, text: str, sig_b64: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64)).verify(base64.b64decode(sig_b64), text.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class CloudState:
    """Everything the proxy remembers about one (cloud url, api key) pair, in a private directory outside the repo."""
    def __init__(self, url: str, api_key: str, root: str | Path | None = None):
        tag = hashlib.sha256(f"{url.rstrip('/')}|{api_key[:12]}".encode()).hexdigest()[:16]
        self.dir = Path(root).expanduser() if root else Path(STATE_ROOT).expanduser() / tag
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.policy_file, self.bundle_file = self.dir / "policy.json", self.dir / "bundle.json"
        self.trust_file, self.cursor_file, self.nonce_file = self.dir / "trust.json", self.dir / "cursor.json", self.dir / "used_nonces.json"

    def _load(self, p: Path, default):
        try:
            return json.loads(p.read_text())
        except (OSError, ValueError):
            return default

    def _save(self, p: Path, obj) -> None:
        _atomic_write(p, json.dumps(obj).encode())

    # trust on first use
    def pinned(self) -> dict | None:
        return self._load(self.trust_file, None)

    def pin(self, public_key: str, workspace_id: str) -> None:
        self._save(self.trust_file, {"public_key": public_key, "workspace_id": workspace_id})

    def cursor(self) -> dict:
        c = self._load(self.cursor_file, {})
        if "ledger_id" not in c:
            c = {"ledger_id": hashlib.sha256(os.urandom(16)).hexdigest()[:12], "seq": 0}
            self._save(self.cursor_file, c)
        return c

    def set_seq(self, seq: int) -> None:
        c = self.cursor(); c["seq"] = seq; self._save(self.cursor_file, c)

    def nonce_used(self, n: str) -> bool:
        return n in self._load(self.nonce_file, [])

    def use_nonce(self, n: str) -> None:
        used = self._load(self.nonce_file, []); used.append(n); self._save(self.nonce_file, used[-5000:])


class CloudClient:
    def __init__(self, url: str, api_key: str, timeout: float = 10.0, transport=None):
        self.url = url.rstrip("/")
        self.http = httpx.Client(base_url=self.url, headers={"Authorization": f"Bearer {api_key}", "User-Agent": "usepanel-proxy"},
                                 timeout=timeout, transport=transport, follow_redirects=False)

    def _req(self, method: str, path: str, **kw) -> dict:
        try:
            r = self.http.request(method, path, **kw)
        except httpx.HTTPError as e:
            raise CloudError(f"cloud unreachable: {type(e).__name__}") from e
        if r.status_code in (401, 403):
            raise CloudError(f"the cloud rejected this API key (HTTP {r.status_code}); it may be revoked")
        if r.status_code >= 400:
            try:
                msg = r.json().get("error", "")
            except ValueError:
                msg = ""
            raise CloudError(f"cloud error {r.status_code}: {msg}"[:200])
        return r.json()

    def policy(self) -> dict: return self._req("GET", "/v1/policy")
    def ping(self) -> dict: return self._req("GET", "/v1/ping")
    def events(self, events: list[dict]) -> dict: return self._req("POST", "/v1/events", json={"events": events})
    def freeze(self) -> dict: return self._req("GET", "/v1/proxy/freeze")
    def tools(self, tools: list[dict]) -> dict: return self._req("POST", "/v1/proxy/tools", json={"tools": tools})
    def request_approval(self, body: dict) -> dict: return self._req("POST", "/v1/approvals", json=body)
    def approval(self, aid: str, wait: int = 0) -> dict:
        return self._req("GET", f"/v1/approvals/{aid}", params={"wait": wait}, timeout=wait + 10 if wait else None)


class PolicyManager:
    """Fetches, verifies, caches and loads the signed policy."""
    def __init__(self, client: CloudClient | None, state: CloudState, pubkey: str | None = None):
        self.client, self.state, self.explicit_pubkey = client, state, pubkey
        self.policy: Policy | None = None
        self.version = 0
        self.workspace_id: str | None = None
        self.public_key: str | None = None

    # -- verification (pure: same code path for a fresh download and for the cache)
    def verify_bundle(self, b: dict, *, pin_if_new: bool) -> tuple[dict, str]:
        pub = b.get("public_key") or ""
        trusted = self.explicit_pubkey or (self.state.pinned() or {}).get("public_key")
        if trusted is None:
            if not pin_if_new:
                raise CloudError("no pinned cloud key for this state; fetch from the cloud first")
            trusted = pub
        if pub != trusted:
            raise CloudError("the cloud's signing key does not match the pinned key (refusing: possible impostor or key rotation; "
                             "pass --cloud-pubkey after verifying the new key out of band)")
        env_s, sig, text = b.get("envelope"), b.get("signature"), b.get("policy_json")
        if not all(isinstance(x, str) for x in (env_s, sig, text)) or not verify_signature(trusted, env_s, sig):
            raise CloudError("policy signature is INVALID; refusing it")
        env = json.loads(env_s)
        if env.get("type") != "policy":
            raise CloudError("not a policy envelope")
        if sha256_hex(text) != env.get("policy_sha256"):
            raise CloudError("policy text does not match the signed hash; refusing it")
        pinned = self.state.pinned()
        ws = (pinned or {}).get("workspace_id") or self.workspace_id
        if ws and env.get("workspace_id") != ws:
            raise CloudError("policy is for a different workspace; refusing it")
        return env, trusted

    def _install(self, b: dict, env: dict, trusted: str) -> Policy:
        if int(env["version"]) < self.version:
            raise CloudError(f"policy version went backwards ({env['version']} < {self.version}); refusing a rollback")
        _atomic_write(self.state.policy_file, b["policy_json"].encode("utf-8"))   # the exact signed bytes: receipts then carry the signed hash
        pol = load_policy(self.state.policy_file)                               # the engine's own validator has the last word
        if pol.sha256 != env["policy_sha256"]:
            raise CloudError("policy file hash mismatch after write")
        self.policy, self.version, self.workspace_id, self.public_key = pol, int(env["version"]), env["workspace_id"], trusted
        return pol

    def load_cached(self) -> Policy | None:
        try:
            b = json.loads(self.state.bundle_file.read_text())
        except (OSError, ValueError):
            return None
        pinned = self.state.pinned()
        if not pinned and not self.explicit_pubkey:
            return None
        try:
            env, trusted = self.verify_bundle(b, pin_if_new=False)
            return self._install(b, env, trusted)
        except (CloudError, FirewallError, KeyError, ValueError) as e:
            log.error("cached policy rejected: %s", e)
            return None

    def refresh(self) -> tuple[Policy, bool]:
        """Download + verify + install. Returns (policy, changed). Raises CloudError if the cloud is unreachable or sends a bad bundle."""
        b = self.client.policy()
        env, trusted = self.verify_bundle(b, pin_if_new=True)
        if not self.state.pinned():
            self.state.pin(trusted, env["workspace_id"])
            log.warning("pinned the cloud signing key %s... for workspace %s (trust on first use)", trusted[:12], env["workspace_id"])
        changed = int(env["version"]) != self.version or self.policy is None or self.policy.sha256 != env["policy_sha256"]
        pol = self._install(b, env, trusted)
        _atomic_write(self.state.bundle_file, json.dumps(b).encode())
        return pol, changed

    def bootstrap(self) -> Policy:
        """Start-up: prefer the cloud; fall back to the verified cache; with neither, refuse to start (fail closed)."""
        cached = self.load_cached()
        try:
            return self.refresh()[0]
        except CloudError as e:
            if cached is not None:
                log.warning("cloud unavailable (%s); enforcing the cached signed policy v%s", e, self.version)
                return cached
            raise CloudError(f"{e}; there is no cached signed policy to fall back on, so Panel will not start (fail closed)") from e


# ------------------------------------------------------------------------------------------------ events and approvals
def receipt_event(ledger_id: str, seq: int, receipt: dict, detail: dict, policy: Policy | None) -> dict:
    """The data-minimised cloud record for one signed receipt. No arguments, only hashes, a verdict, a rule and a scrubbed sentence."""
    from tenthlook_core import receipt as core

    from panel_firewall.firewall.summary import rule_of, summarize
    reasons = receipt["reasons"]
    kv = {r.split("=", 1)[0]: r.split("=", 1)[1] for r in reasons if "=" in r and r.split("=", 1)[0] in
          ("outcome", "tool", "mode", "shadow_would", "policy_version")}
    verdict = _VERDICT.get(receipt["verdict"], "block")
    outcome = kv.get("outcome", "executed")
    shadow = "mode=shadow" in reasons
    would = kv.get("shadow_would")
    cut = next((i for i, r in enumerate(reasons) if r.startswith("outcome=")), len(reasons))
    plain = reasons[:cut]                 # the verdict's own reasons come first; the key=value bookkeeping follows
    rule = rule_of(plain[0]) if plain and verdict != "allow" else None
    amount = None
    args = (detail.get("action") or {}).get("args")
    if isinstance(args, dict) and policy is not None:
        v = args.get((policy.rule_for(detail["tool"]) or {}).get("amount_field", "amount"))
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0:
            amount = float(v)
    ev_name = "shadow" if (shadow and would) else {"executed": "executed", "blocked": "blocked"}.get(outcome, outcome)
    summary = summarize(detail["tool"], ev_name, {"amount": amount, "reasons": plain, "would": would})
    out = {"id": f"{ledger_id}-{seq}", "ts": float(detail.get("timestamp") or time.time()), "tool": detail["tool"], "verdict": verdict,
           "outcome": outcome if outcome in ("executed", "blocked", "failed", "dry_run", "replayed", "frozen", "unfrozen") else "executed",
           "mode": "shadow" if shadow else "enforce", "summary": summary, "action_sha256": receipt["artifact_sha256"],
           "receipt_sha256": core.receipt_hash(receipt), "policy_sha256": receipt["policy_sha256"],
           "receipt": receipt}                   # the signed receipt itself: hashes, verdict and reasons, never arguments; the cloud verifies the signature
    if would:
        out["shadow_would"] = would
    if rule:
        out["rule"] = rule
    if amount is not None:
        out["amount"] = amount
    return out


_HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def minimise_tools(tools: list) -> list[dict]:
    """What the cloud may see of an upstream tools/list: the tool name, each parameter's NAME and JSON TYPE, and boolean annotation hints.
    No descriptions (they can carry instructions or data), no defaults, no enums, no examples."""
    out = []
    for t in tools:
        if not isinstance(t, dict) or not isinstance(t.get("name"), str):
            continue
        props = ((t.get("inputSchema") or {}).get("properties") or {}) if isinstance(t.get("inputSchema"), dict) else {}
        item: dict = {"name": t["name"],
                      "properties": {k: (v.get("type") if isinstance(v, dict) and isinstance(v.get("type"), str) else "any")[:20]
                                     for k, v in list(props.items())[:60] if isinstance(k, str)}}
        ann = {k: v for k, v in (t.get("annotations") or {}).items() if k in _HINTS and isinstance(v, bool)} if isinstance(t.get("annotations"), dict) else {}
        if ann:
            item["annotations"] = ann
        out.append(item)
    return out[:300]


class CloudSync:
    """Background worker: policy refresh, event upload, approval registration and decision pick-up. Every method is safe to call
    repeatedly and never raises on network trouble (the proxy keeps enforcing locally)."""
    def __init__(self, client: CloudClient, state: CloudState, pm: PolicyManager, fw, *, forced_shadow: bool = False,
                 policy_every: float = 30.0, tick_every: float = 3.0, clock=time.time, on_change=None):
        self.client, self.state, self.pm, self.fw, self.forced_shadow = client, state, pm, fw, forced_shadow
        self.policy_every, self.tick_every, self.clock, self.on_change = policy_every, tick_every, clock, on_change
        self._last_policy = 0.0
        self._registered: dict[str, float] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.online = True

    # -- tools/list report (for the dashboard's "Suggested rules"); fire-and-forget, only re-sent when it changes
    def report_tools(self, tools: list) -> None:
        payload = minimise_tools(tools)
        if not payload:
            return
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if digest == getattr(self, "_tools_digest", None):
            return
        def go():
            try:
                self.client.tools(payload)
                self._tools_digest = digest
            except CloudError as e:
                log.warning("could not report the tool list to the cloud (%s); suggestions will be missing until the next tools/list", e)
        threading.Thread(target=go, daemon=True).start()

    # -- policy
    def apply_policy(self, pol: Policy) -> None:
        old = self.fw.policy
        self.fw.policy = pol
        for c in self.fw.connectors:
            if hasattr(c, "policy"):
                c.policy = pol
        self.fw.mode = "shadow" if self.forced_shadow else pol.mode
        if old is not pol and old.sha256 != pol.sha256:
            log.warning("cloud policy v%s active (mode: %s)%s", self.pm.version, self.fw.mode,
                        " [local --shadow overrides]" if self.forced_shadow and pol.mode != "shadow" else "")
            if self.on_change:
                self.on_change(pol)

    def refresh_policy(self) -> bool:
        try:
            pol, changed = self.pm.refresh()
        except CloudError as e:
            self._offline(e)
            return False
        self._online()
        if changed:
            self.apply_policy(pol)
        return True

    # -- events
    def upload_events(self, batch: int = 100) -> int:
        cur = self.state.cursor()
        led, sent = self.fw.ledger, 0
        evs = [e for e in led.events(since_seq=cur["seq"], limit=1000) if e["event"] == "receipt" and "receipt" in e["data"]]
        last = cur["seq"]
        all_seq = led.events(since_seq=cur["seq"], limit=1000)
        if all_seq:
            last = all_seq[-1]["seq"]
        recs = [receipt_event(cur["ledger_id"], e["seq"], e["data"]["receipt"], e["data"]["detail"], self.fw.policy) for e in evs]
        for i in range(0, len(recs), batch):
            try:
                self.client.events(recs[i:i + batch])
            except CloudError as e:
                self._offline(e)
                if i:   # advance only past what was accepted
                    self.state.set_seq(evs[i - 1]["seq"])
                return sent
            sent += len(recs[i:i + batch])
        if all_seq and last > cur["seq"]:
            self.state.set_seq(last)
        if recs:
            self._online()
        return sent

    # -- approvals
    def register_pending(self) -> int:
        n = 0
        for p in self.fw.ledger.pending():
            aid = p["approval_id"]
            if aid in self._registered and self.clock() - self._registered[aid] < 600:
                continue
            args = p.get("args") or {}
            rule = self.fw.policy.rule_for(p["tool"]) or {}
            amt = args.get(rule.get("amount_field", "amount")) if isinstance(args, dict) else None
            amt = float(amt) if isinstance(amt, (int, float)) and not isinstance(amt, bool) and amt >= 0 else None
            from panel_firewall.firewall.summary import summarize
            body = {"approval_id": aid, "tool": p["tool"], "action_sha256": p["action_sha"], "amount": amt,
                    "summary": summarize(p["tool"], "pending", {"amount": amt, "reasons": p.get("reasons")}),
                    "reasons": "; ".join(p.get("reasons") or []), "ttl_seconds": 900}
            try:
                self.client.request_approval(body)
            except CloudError as e:
                self._offline(e)
                return n
            self._registered[aid] = self.clock()
            n += 1
        return n

    def check_decisions(self, wait: int = 0) -> int:
        applied = 0
        pend = {p["approval_id"]: p for p in self.fw.ledger.pending()}
        for aid in list(self._registered):
            if aid not in pend:                       # decided locally (PIN) or executed: stop tracking
                self._registered.pop(aid, None)
                continue
            try:
                r = self.client.approval(aid, wait=wait)
            except CloudError as e:
                self._offline(e)
                return applied
            if r.get("status") in ("approved", "denied") and self.apply_decision(aid, pend[aid], r):
                applied += 1
                self._registered.pop(aid, None)
        return applied

    def apply_decision(self, aid: str, pending: dict, r: dict) -> bool:
        """Accept a decision only if EVERYTHING checks out. Any doubt: ignore it and leave the action held."""
        pub = self.pm.public_key
        text, sig = r.get("decision"), r.get("signature")
        if not (isinstance(text, str) and isinstance(sig, str) and pub and verify_signature(pub, text, sig)):
            log.error("cloud decision for %s has an invalid signature; ignored (action stays held)", aid)
            return False
        d = json.loads(text)
        why = None
        if d.get("type") != "decision": why = "wrong type"
        elif d.get("workspace_id") != self.pm.workspace_id: why = "different workspace"
        elif d.get("approval_id") != aid: why = "different approval id"
        elif d.get("action_sha256") != pending["action_sha"]: why = "bound to a different action"
        elif d.get("decision") not in ("approve", "deny"): why = "unknown decision"
        elif self.clock() > float(d.get("expires_at", 0)): why = "expired"
        elif not d.get("nonce") or self.state.nonce_used(d["nonce"]): why = "nonce already used"
        if why:
            log.error("cloud decision for %s refused (%s); action stays held", aid, why)
            return False
        self.state.use_nonce(d["nonce"])               # consumed before it is applied: a crash can never allow a second use
        ok, msg = self.fw.ledger.approve(aid, f"cloud:{d.get('decided_by', '?')}", deny=(d["decision"] == "deny"),
                                         reason="decided in Panel Cloud", proof={"cloud_nonce": d["nonce"], "cloud_sig": sig[:32], "cloud_decided_at": d.get("decided_at")})
        log.info("cloud decision for %s: %s (%s)", aid, d["decision"], msg)
        return ok

    def check_unfreeze(self) -> bool:
        """If this proxy is frozen by its circuit breaker, ask the cloud whether a signed unfreeze decision exists for THIS freeze, and apply it
        only if everything checks out (signature, workspace, the exact freeze receipt, expiry, single-use nonce)."""
        if self.fw.frozen() is None:
            return False
        from tenthlook_core import receipt as core
        frozen = [r for r in self.fw.ledger.receipts() if "outcome=frozen" in r["reasons"]]
        if not frozen:
            return False
        local = core.receipt_hash(frozen[-1])
        try:
            r = self.client.freeze()
        except CloudError as e:
            self._offline(e); return False
        self._online()
        pub, text, sig = self.pm.public_key, (r.get("unfreeze") or {}).get("decision"), (r.get("unfreeze") or {}).get("signature")
        if not text:
            return False
        if not (isinstance(text, str) and isinstance(sig, str) and pub and verify_signature(pub, text, sig)):
            log.error("cloud unfreeze has an invalid signature; ignored (writes stay frozen)"); return False
        d = json.loads(text); why = None
        if d.get("type") != "unfreeze": why = "wrong type"
        elif d.get("workspace_id") != self.pm.workspace_id: why = "different workspace"
        elif d.get("freeze_receipt_sha256") != local: why = "bound to a different freeze"
        elif self.clock() > float(d.get("expires_at", 0)): why = "expired"
        elif not d.get("nonce") or self.state.nonce_used(d["nonce"]): why = "nonce already used"
        if why:
            log.error("cloud unfreeze refused (%s); writes stay frozen", why); return False
        self.state.use_nonce(d["nonce"])
        ok, msg = self.fw.unfreeze(f"cloud:{d.get('decided_by', '?')}", proof={"cloud_nonce": d["nonce"], "cloud_sig": sig[:32], "cloud_decided_at": d.get("decided_at")})
        log.info("cloud unfreeze: %s", msg)
        return ok

    # -- loop
    def _offline(self, e):
        if self.online:
            log.warning("%s; continuing with the cached policy (held actions stay held)", e)
        self.online = False

    def _online(self):
        if not self.online:
            log.warning("cloud connection restored")
        self.online = True

    def tick(self) -> None:
        if self.clock() - self._last_policy >= self.policy_every:
            self._last_policy = self.clock()
            self.refresh_policy()
        self.upload_events()
        self.register_pending()
        self.check_decisions(wait=0)
        self.check_unfreeze()

    def start(self) -> None:
        def loop():
            while not self._stop.is_set():
                try:
                    self.tick()
                except Exception:
                    log.exception("cloud sync tick failed")
                self._stop.wait(self.tick_every)
        self._thread = threading.Thread(target=loop, name="panel-cloud-sync", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


# ------------------------------------------------------------------------------------------------ saved cloud config (`usepanel init --token`)
DEFAULT_CLOUD_URL = "https://app.usepanel.dev"
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def config_dir() -> Path:
    """Where `usepanel init --token` saves the cloud config: $PANEL_CONFIG_DIR, else $XDG_CONFIG_HOME/usepanel, else ~/.config/usepanel."""
    if os.environ.get("PANEL_CONFIG_DIR"):
        return Path(os.environ["PANEL_CONFIG_DIR"]).expanduser()
    return Path(os.environ.get("XDG_CONFIG_HOME") or "~/.config").expanduser() / "usepanel"


def config_path() -> Path:
    return config_dir() / "cloud.json"


def normalize_cloud_url(url: str) -> str:
    """Strip trailing slashes and refuse anything but https:// (plain http:// only for localhost / 127.0.0.1)."""
    url = (url or "").strip().rstrip("/")
    try:
        u = httpx.URL(url)
    except Exception as e:
        raise FirewallError(f"not a valid --cloud-url: {url!r}") from e
    if u.scheme not in ("https", "http") or not u.host:
        raise FirewallError(f"--cloud-url must look like https://app.usepanel.dev (got {url!r})")
    if u.scheme == "http" and u.host not in _LOCAL_HOSTS:
        raise FirewallError(f"refusing plain http:// for {u.host}: the API key would cross the network unencrypted. Use https:// "
                            "(http:// is allowed only for localhost and 127.0.0.1)")
    return url


def load_saved_config() -> dict | None:
    """The config `usepanel init --token` wrote, or None if there is none. A damaged file is an error, not a silent fallback."""
    p = config_path()
    try:
        d = json.loads(p.read_text())
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise FirewallError(f"cannot read the saved Panel Cloud config {p} ({type(e).__name__}); run the `usepanel init --token ...` "
                            "command from the dashboard again, or delete the file") from e
    if not isinstance(d, dict) or not all(isinstance(d.get(k), str) and d.get(k) for k in ("cloud_url", "api_key")):
        raise FirewallError(f"the saved Panel Cloud config {p} is incomplete; run the `usepanel init --token ...` command from the dashboard again")
    return d


def save_config(cfg: dict) -> Path:
    """Write the cloud config atomically: file mode 600, directory mode 700."""
    p = config_path()
    if not p.parent.exists():
        p.parent.mkdir(parents=True, mode=0o700)
    os.chmod(p.parent, 0o700)
    _atomic_write(p, (json.dumps(cfg, indent=2) + "\n").encode())
    return p


def redeem_setup_token(cloud_url: str, token: str, machine: str, transport=None, timeout: float = 15.0) -> dict:
    """Trade a one-time setup token (pit_..., single use, 10 minutes) for a workspace API key. No Authorization header is sent."""
    try:
        with httpx.Client(base_url=cloud_url, headers={"User-Agent": "usepanel-init"}, timeout=timeout, transport=transport,
                          follow_redirects=False) as c:
            r = c.post("/v1/proxy/init", json={"token": token, "machine": machine})
    except httpx.HTTPError as e:
        raise CloudError(f"could not reach Panel Cloud at {cloud_url} ({type(e).__name__}). Check the --cloud-url and your network, "
                         "then run the command again; if it keeps failing, make a new setup command in the dashboard.") from e
    try:
        body = r.json()
    except ValueError:
        body = {}
    body = body if isinstance(body, dict) else {}
    if r.status_code == 404:
        raise CloudError("this setup command is invalid, already used or expired (they work once, for 10 minutes). "
                         "Make a new one in the Panel Cloud dashboard and run it again.")
    if r.status_code == 429:
        ra = body.get("retry_after")
        wait = f"wait {int(ra)} seconds" if isinstance(ra, (int, float)) and not isinstance(ra, bool) and ra > 0 else "wait a minute"
        raise CloudError(f"too many setup attempts; {wait} and run the command again.")
    if r.status_code != 200:
        msg = body.get("error") if isinstance(body.get("error"), str) else ""
        msg = "".join(ch for ch in msg if ch.isprintable())[:200]
        raise CloudError(f"Panel Cloud refused the setup (HTTP {r.status_code}){': ' + msg if msg else ''}. Check the --cloud-url, "
                         "or make a new setup command in the dashboard.")
    key, ws = body.get("api_key"), body.get("workspace")
    if not (isinstance(key, str) and key.startswith("pcl_") and isinstance(ws, dict) and isinstance(ws.get("id"), str) and ws["id"]):
        raise CloudError(f"unexpected reply from {cloud_url}/v1/proxy/init (no API key or workspace); is --cloud-url the Panel Cloud API?")
    return {"api_key": key, "workspace_id": ws["id"], "workspace_name": ws.get("name") if isinstance(ws.get("name"), str) else "",
            "key_id": body.get("key_id") if isinstance(body.get("key_id"), str) else ""}


def _explicit_api_key(a) -> tuple[str | None, str]:
    """--api-key / PANEL_API_KEY / --api-key-file, exactly as before the saved config existed (a manual override)."""
    if getattr(a, "api_key", None):
        return a.api_key, "--api-key"
    if os.environ.get("PANEL_API_KEY"):
        return os.environ["PANEL_API_KEY"], "PANEL_API_KEY"
    kf = getattr(a, "api_key_file", None)
    if kf:
        try:
            return Path(kf).expanduser().read_text().strip(), f"--api-key-file {kf}"
        except OSError as e:
            raise FirewallError(f"cannot read --api-key-file {kf} ({type(e).__name__})") from e
    return None, ""


def _same_url(x: str, y: str) -> bool:
    return x.strip().rstrip("/").lower() == y.strip().rstrip("/").lower()


def resolve_api_key(a, cloud_url: str | None = None) -> tuple[str | None, str]:
    """(key, where it came from). Flags and PANEL_API_KEY win; then the saved config, but only for the cloud it was made for, so a key
    is never sent to a different --cloud-url than the one that issued it."""
    key, src = _explicit_api_key(a)
    if src:                                   # an explicit choice is never silently replaced by the saved config
        return key or None, src
    saved = load_saved_config()
    url = cloud_url or getattr(a, "cloud_url", None)
    if saved and (not url or _same_url(saved["cloud_url"], url)):
        return saved["api_key"], f"saved config {config_path()}"
    return None, ""


def apply_saved_cloud_url(a) -> dict | None:
    """With no --cloud-url and no --policy, use the cloud saved by `usepanel init --token`. Returns the saved config if it was used."""
    if getattr(a, "cloud_url", None) or getattr(a, "policy", None):
        return None
    saved = load_saved_config()
    if saved:
        a.cloud_url = saved["cloud_url"]
    return saved


def saved_config_mismatch(url: str | None) -> str:
    """A note when the saved config exists but is for another cloud (its key is then not used), else ''."""
    try:
        saved = load_saved_config()
    except FirewallError:
        return ""
    if saved and url and not _same_url(saved["cloud_url"], url):
        return f" (the saved config from `usepanel init --token` is for {saved['cloud_url']}, not {url}, so its key is not used)"
    return ""


def _no_key_message(a) -> str:
    return ("--cloud-url needs an API key: run the `usepanel init --token ...` command from the dashboard, or pass --api-key-file FILE "
            "or set PANEL_API_KEY" + saved_config_mismatch(getattr(a, "cloud_url", None)))


def read_api_key(a) -> str:
    key, src = resolve_api_key(a)
    if not key:
        raise FirewallError(f"{src} is empty" if src else _no_key_message(a))
    if getattr(a, "api_key", None):
        log.warning("--api-key is visible in the process list; prefer --api-key-file or PANEL_API_KEY")
    return key


def bootstrap_cloud(a) -> tuple[CloudClient, CloudState, PolicyManager]:
    """Resolve the cloud policy BEFORE the firewall is built. Sets a.policy to the verified policy file."""
    key = read_api_key(a)
    state = CloudState(a.cloud_url, key, getattr(a, "cloud_state_dir", None))
    client = CloudClient(a.cloud_url, key)
    pm = PolicyManager(client, state, getattr(a, "cloud_pubkey", None))
    pm.bootstrap()
    a.policy = str(state.policy_file)
    if not getattr(a, "ledger", None):
        a.ledger = str(state.dir / "panel-ledger.sqlite")
    return client, state, pm
