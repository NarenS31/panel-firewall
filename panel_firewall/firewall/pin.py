"""Approval PIN: makes `usepanel approve` and the local UI's Approve button require a secret only the human types.

What it is:
  * `usepanel pin set` reads a PIN/passphrase from the controlling terminal (/dev/tty) only: never from an argument, stdin
    or an environment variable. Only a salted scrypt hash is stored (mode 600, `~/.config/panel/approval_pin.json`, outside
    the repo). The same file keeps the failed-attempt counter (lockout survives restarts) and a random MAC key.
  * Approving needs a one-time ApprovalToken. The gate verifies the PIN (rate limited), then mints a token bound to the exact
    pending action (approval id + action sha256 + decision), valid for 60 seconds, usable once. `Ledger.approve` refuses an
    approval without a valid token when a guard is installed, and records the token's nonce so a replay is refused.
  * The CLI refuses unless stdin, stdout and /dev/tty are the same interactive terminal, so a background agent subprocess
    (pipes, no controlling terminal) cannot feed it a PIN.

What it is not: protection against anything that runs as your OS user with full access (it can rewrite the PIN file or the
ledger directly), against something that reads your keystrokes or screen, or against a human who shares the PIN. See README
"Security model". Denying never needs the PIN (refusing an action is the safe direction).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
import time
from pathlib import Path

from panel_firewall.firewall.types import FirewallError, canonical

DEFAULT_PIN_FILE = "~/.config/panel/approval_pin.json"
MIN_PIN_LEN = 6
SCRYPT_N = 2 ** 15            # 32 MiB; stored in the file so it can be raised later
TOKEN_TTL = 60.0
MAX_FAILURES = 5              # consecutive wrong PINs before a lockout
LOCK_BASE = 300.0             # first lockout 5 min, doubling, capped at 1 h
LOCK_CAP = 3600.0
FAIL_DELAY = 0.0              # test hook: a fixed sleep after a wrong PIN (0 = none)


class PinError(FirewallError):
    """A refused PIN operation. `.locked_for` is set (seconds) when the cause is a lockout."""
    def __init__(self, msg: str, locked_for: float = 0.0):
        super().__init__(msg)
        self.locked_for = locked_for


# ------------------------------------------------------------------------------------------------ terminal input
def read_secret_from_tty(prompt: str) -> str:
    """Read a line with echo off from the controlling terminal. Refuses (PinError) unless stdin, stdout and /dev/tty are the
    same interactive terminal. Never falls back to stdin (unlike getpass)."""
    try:
        import termios
    except ImportError as e:                          # pragma: no cover (Windows)
        raise PinError("refused: PIN entry needs a POSIX terminal") from e
    try:
        if not (os.isatty(0) and os.isatty(1)):
            raise PinError("refused: approving needs an interactive terminal (stdin and stdout must be a terminal, not a pipe or file)")
        tty = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError as e:
        raise PinError("refused: no controlling terminal (/dev/tty); a PIN can only be typed by a human at a terminal") from e
    try:
        if os.tcgetpgrp(tty) != os.tcgetpgrp(0):      # same terminal (macOS names /dev/tty differently, so compare foreground groups)
            raise PinError("refused: stdin is not this process's controlling terminal")
        old = termios.tcgetattr(tty)
        new = termios.tcgetattr(tty)
        new[3] &= ~termios.ECHO
        os.write(tty, prompt.encode())
        termios.tcsetattr(tty, termios.TCSAFLUSH, new)
        try:
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = os.read(tty, 1)
                if not chunk:
                    raise PinError("refused: terminal closed before a PIN was entered")
                buf += chunk
        finally:
            termios.tcsetattr(tty, termios.TCSAFLUSH, old)
            os.write(tty, b"\n")
        return buf.decode("utf-8", "replace").rstrip("\r\n")
    finally:
        os.close(tty)


# ------------------------------------------------------------------------------------------------ the store
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _hash(pin: str, salt: bytes, n: int, r: int = 8, p: int = 1) -> bytes:
    return hashlib.scrypt(pin.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * 1024 * 1024)


class PinStore:
    def __init__(self, path: str | Path | None = None, clock=time.time):
        self.path = Path(path or os.environ.get("PANEL_PIN_FILE") or DEFAULT_PIN_FILE).expanduser()
        self.clock = clock

    # -- file io (every read-modify-write holds an exclusive flock on a sidecar so two processes cannot race the counter)
    def _lock(self):
        import fcntl
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def _read(self) -> dict | None:
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            return None
        except (ValueError, OSError) as e:
            raise PinError(f"{self.path}: unreadable PIN file ({type(e).__name__}); refusing to approve") from e

    def _write(self, d: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".pin-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(d, f)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def is_set(self) -> bool:
        return self.path.is_file()

    def _check_mode(self) -> None:
        if stat.S_IMODE(self.path.stat().st_mode) & 0o077:
            raise PinError(f"{self.path} is readable by others; run `chmod 600 {self.path}`; refusing to approve")

    # -- public api
    def set_pin(self, new_pin: str, current_pin: str | None = None, n: int = SCRYPT_N) -> None:
        """Create or change the PIN. Changing requires the current PIN (and counts against the lockout)."""
        if len(new_pin) < MIN_PIN_LEN:
            raise PinError(f"the PIN must be at least {MIN_PIN_LEN} characters")
        if self.is_set():
            self.verify(current_pin or "")
        fd = self._lock()
        try:
            salt = secrets.token_bytes(16)
            self._write({"v": 1, "kdf": "scrypt", "n": n, "r": 8, "p": 1, "salt": _b64(salt), "hash": _b64(_hash(new_pin, salt, n)),
                         "mac_key": _b64(secrets.token_bytes(32)), "failures": 0, "locked_until": 0.0, "lock_level": 0})
        finally:
            os.close(fd)

    def status(self) -> dict:
        if not self.is_set():
            return {"set": False}
        d = self._read()
        left = max(0.0, d.get("locked_until", 0.0) - self.clock())
        return {"set": True, "locked_for": left, "failures": d.get("failures", 0)}

    def verify(self, pin: str) -> None:
        """Raises PinError on a wrong PIN, a missing PIN, or while locked out. Wrong guesses are counted on disk."""
        if not self.is_set():
            raise PinError("no approval PIN is set; run `usepanel pin set` first (approvals are refused without one)")
        fd = self._lock()
        try:
            self._check_mode()
            d = self._read()
            now = self.clock()
            if d.get("locked_until", 0.0) > now:
                raise PinError(f"too many wrong PINs; locked for another {int(d['locked_until'] - now) + 1}s", d["locked_until"] - now)
            ok = hmac.compare_digest(_hash(pin, base64.b64decode(d["salt"]), d["n"], d.get("r", 8), d.get("p", 1)), base64.b64decode(d["hash"]))
            if ok:
                if d.get("failures") or d.get("lock_level"):
                    d.update(failures=0, lock_level=0, locked_until=0.0)
                    self._write(d)
                return
            d["failures"] = d.get("failures", 0) + 1
            if d["failures"] >= MAX_FAILURES:
                lock = min(LOCK_CAP, LOCK_BASE * (2 ** d.get("lock_level", 0)))
                d.update(failures=0, lock_level=d.get("lock_level", 0) + 1, locked_until=now + lock)
                self._write(d)
                raise PinError(f"wrong PIN; too many attempts, locked for {int(lock)}s", lock)
            self._write(d)
            if FAIL_DELAY:
                time.sleep(FAIL_DELAY)
            raise PinError(f"wrong PIN ({MAX_FAILURES - d['failures']} attempts left before a lockout)")
        finally:
            os.close(fd)

    def _mac_key(self) -> bytes:
        d = self._read()
        if not d:
            raise PinError("no approval PIN is set")
        return base64.b64decode(d["mac_key"])

    # -- tokens
    def mint(self, approval_id: str, action_sha: str, deny: bool = False) -> dict:
        """Only call after `verify` succeeded. A token authorises ONE decision on ONE pending action, for TOKEN_TTL seconds."""
        body = {"approval_id": approval_id, "action_sha": action_sha, "deny": bool(deny), "nonce": secrets.token_hex(16),
                "exp": self.clock() + TOKEN_TTL}
        return {**body, "mac": hmac.new(self._mac_key(), canonical(body).encode(), hashlib.sha256).hexdigest()}

    def check_token(self, token, approval_id: str, action_sha: str, deny: bool) -> str | None:
        """None if valid for exactly this action and decision, else the reason. Single-use is enforced by the ledger."""
        if not isinstance(token, dict):
            return "an approval PIN token is required"
        try:
            body = {k: token[k] for k in ("approval_id", "action_sha", "deny", "nonce", "exp")}
            good = hmac.new(self._mac_key(), canonical(body).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(good, str(token.get("mac", ""))):
                return "approval token is not valid (bad signature)"
        except (KeyError, TypeError, PinError):
            return "approval token is not valid"
        if body["approval_id"] != approval_id or body["action_sha"] != action_sha or body["deny"] != bool(deny):
            return "approval token is for a different action"
        if self.clock() > body["exp"]:
            return "approval token expired"
        return None


class ApprovalGate:
    """The one place a human decision gets into the ledger. `pin` is typed by the human (terminal) or submitted in the UI form."""
    def __init__(self, ledger, store: PinStore | None = None):
        self.ledger, self.store = ledger, store or PinStore()
        ledger.guard = self.store            # from now on this ledger object refuses approvals without a valid token

    def decide(self, approval_id: str, who: str, pin: str | None, deny: bool = False, reason: str = "") -> tuple[bool, str]:
        action_sha = self.ledger.pending_action_sha(approval_id)
        if action_sha is None:
            return False, f"no pending action with id {approval_id}"
        token = None
        if not deny:
            if not pin:
                raise PinError("the approval PIN is required")
            self.store.verify(pin)
            token = self.store.mint(approval_id, action_sha, deny=False)
        return self.ledger.approve(approval_id, who, deny=deny, reason=reason, token=token)
