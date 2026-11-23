"""Run a command with a real controlling terminal (a pty) so tests can play the human who types a PIN."""
import fcntl
import os
import pty
import select
import subprocess
import sys
import termios
import time


def run_on_tty(argv, answers, env=None, cwd=None, timeout=30):
    """Start argv with a pty as stdin/stdout/stderr AND controlling terminal. Each time the program ends a line with a prompt
    (": "), send the next answer. Returns (exit code, everything it printed)."""
    master, slave = pty.openpty()

    def child():
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    p = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env={**os.environ, **(env or {})}, cwd=cwd,
                         start_new_session=True, preexec_fn=child, close_fds=True)
    os.close(slave)
    out, sent, answered_at, end = b"", 0, -1, time.time() + timeout
    try:
        while time.time() < end:
            r, _, _ = select.select([master], [], [], 0.1)
            if r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
                if out.endswith(b": ") and sent < len(answers) and len(out) != answered_at:
                    time.sleep(0.15)                       # let the child switch echo off before we type
                    os.write(master, (answers[sent] + "\n").encode())
                    sent += 1
                    answered_at = len(out)
            elif p.poll() is not None:
                break
        p.wait(timeout=5)
    finally:
        if p.poll() is None:
            p.kill()
        os.close(master)
    return p.returncode, out.decode("utf-8", "replace")


def panel(*args):
    return [sys.executable, "-m", "panel_firewall.firewall", *args]
