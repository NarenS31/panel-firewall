"""`panel` command line. Subcommands: keygen, init, proxy, serve, pending, approve, deny, ui, verify-receipt, export-receipts."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from pathlib import Path

from panel_firewall.firewall.types import FirewallError, UpstreamError


def _ledger(a):
    from panel_firewall.firewall.config import ledger_path
    from panel_firewall.firewall.ledger import Ledger
    from panel_firewall.firewall.policy import load_policy
    return Ledger(ledger_path(load_policy(a.policy), a.ledger) if a.policy else a.ledger)


def cmd_keygen(a):
    from panel_firewall.firewall.receipts import DEFAULT_KEY, generate_key
    p = generate_key(a.path or DEFAULT_KEY, force=a.force)
    print(f"private key: {p} (mode 600, keep it outside the repo)\npublic key:  {p}.pub")
    return 0


def cmd_demo(a):
    """Zero-config walkthrough of the firewall in a temp dir (no key, policy, PIN or network needed)."""
    from panel_firewall.firewall.demo import run_demo
    return run_demo(color=False if a.no_color else None)


def cmd_fingerprint(a):
    """Print the fingerprint of this machine's receipt-signing key, to compare with the one Panel Cloud shows before an owner confirms it."""
    from panel_firewall.firewall.receipts import Signer, fingerprint
    s = Signer.load(a.key)
    print(f"Receipt signing key: {s.path}\nFingerprint:         {fingerprint(s.pubkey)}\n"
          "In Panel Cloud, confirm the key only if its fingerprint is exactly this one.")
    return 0


def cmd_pending(a):
    p = _ledger(a).pending()
    if not p:
        print("nothing pending")
    for x in p:
        print(f"{x['approval_id']}  {x['tool']}  {json.dumps(x['args'])}\n    why held: {'; '.join(x['reasons'])}")
    return 0


def _decide(a, deny):
    from panel_firewall.firewall.pin import (
        ApprovalGate,
        PinError,
        PinStore,
        read_secret_from_tty,
    )
    led = _ledger(a)
    who = a.who or getpass.getuser()
    store = PinStore(a.pin_file)
    pin = None
    try:
        gate = ApprovalGate(led, store)
        if not deny:                       # refusing an action never needs the PIN; approving always does
            if not store.is_set():
                raise PinError("no approval PIN is set; run `usepanel pin set` first (approvals are refused without one)")
            pin = read_secret_from_tty("Approval PIN (typed by you, never by the agent): ")
        ok, msg = gate.decide(a.id, who, pin, deny=deny, reason=a.reason or "")
    except PinError as e:
        print(f"NOT DONE: {e}")
        return 1
    print(("OK: " if ok else "NOT DONE: ") + msg + (f" by {who}" if ok else ""))
    return 0 if ok else 1


def cmd_unfreeze(a):
    """Lift a circuit-breaker freeze. Needs the approval PIN, typed on the terminal, like an approval."""
    from panel_firewall.firewall.config import ledger_path
    from panel_firewall.firewall.engine import Firewall
    from panel_firewall.firewall.ledger import Ledger
    from panel_firewall.firewall.pin import (
        ApprovalGate,
        PinError,
        PinStore,
        read_secret_from_tty,
    )
    from panel_firewall.firewall.policy import load_policy
    from panel_firewall.firewall.receipts import Signer
    pol = load_policy(a.policy) if a.policy else None
    led = Ledger(ledger_path(pol, a.ledger) if pol else a.ledger)
    fs = led.freeze_state()
    if fs is None:
        print("Writes are not frozen.")
        return 0
    print(f"Frozen since {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(fs['ts']))}: {fs.get('reason', '')}")
    store = PinStore(a.pin_file)
    try:
        ApprovalGate(led, store)
        if not store.is_set():
            raise PinError("no approval PIN is set; run `usepanel pin set` first")
        store.verify(read_secret_from_tty("Approval PIN (typed by you, never by the agent): "))
        ref = f"freeze-{fs['seq']}"
        token = store.mint(ref, ref, deny=False)
        fw = Firewall(pol, led, Signer.load(getattr(a, "key", None)), []) if pol else None
        ok, msg = (fw.unfreeze(a.who or getpass.getuser(), token) if fw else led.unfreeze(a.who or getpass.getuser(), token))
    except PinError as e:
        print(f"NOT DONE: {e}")
        return 1
    print(("OK: " if ok else "NOT DONE: ") + msg)
    return 0 if ok else 1


def cmd_pin(a):
    from panel_firewall.firewall.pin import PinError, PinStore, read_secret_from_tty
    store = PinStore(a.pin_file)
    if a.action == "status":
        st = store.status()
        print("no approval PIN set" if not st["set"] else
              f"approval PIN set ({store.path}); " + (f"LOCKED for {int(st['locked_for'])}s" if st["locked_for"] > 0 else "not locked"))
        return 0
    try:
        cur = read_secret_from_tty("Current PIN: ") if store.is_set() else None
        new = read_secret_from_tty("New PIN or passphrase (6+ characters): ")
        if read_secret_from_tty("Repeat it: ") != new:
            print("NOT DONE: the two entries differ")
            return 1
        store.set_pin(new, cur)
    except PinError as e:
        print(f"NOT DONE: {e}")
        return 1
    print(f"approval PIN saved (salted scrypt hash, mode 600) at {store.path}")
    return 0


def _since(a):
    from panel_firewall.firewall.summary import parse_since
    try:
        return parse_since(a.since) if a.since else 0.0
    except ValueError as e:
        raise FirewallError(str(e))


def cmd_report(a):
    from panel_firewall.firewall.policy import load_policy
    from panel_firewall.firewall.summary import build_report, format_report
    rep = build_report(_ledger(a), _since(a), load_policy(a.policy) if a.policy else None)
    print(json.dumps(rep, indent=2) if a.json else format_report(rep, a.since or ""))
    return 0


def cmd_suggest(a):
    """Rule suggestions from observed traffic. Prints templated YAML; a human accepts; accepted rules go to a PROPOSAL file, never the live policy."""
    from panel_firewall.firewall import suggest
    from panel_firewall.firewall.policy import load_policy
    pol = load_policy(a.policy) if a.policy else None
    if a.accept in ("all", "review") and pol is None:
        raise FirewallError("--policy is required to write a proposal")
    res = suggest.analyze(_ledger(a), pol, _since(a), a.min_calls, from_shadow=a.from_shadow)
    if a.json:
        print(json.dumps(res, indent=2, default=list))
        return 0
    print(suggest.format_suggestions(res, a.since or "7d", a.from_shadow))
    if not res["tools"]:
        return 0
    if a.accept == "skip" or (a.accept is None and not sys.stdin.isatty()):
        print("\nNothing was changed. Re-run in a terminal to review, or pass --accept all|review.")
        return 0
    first = [True]

    def ask(q):
        if a.accept == "all":
            return "all"
        if a.accept == "review" and first[0]:
            first[0] = False
            return "review"
        first[0] = False
        return input(q)
    accepted = suggest.review(res, ask)
    if not accepted:
        print("Skipped. Nothing was changed.")
        return 0
    out = suggest.write_proposal(a.policy, pol.raw, accepted, a.out)
    print(f"\nWrote {sum(len(r) for r in accepted.values())} accepted rule(s) to {out}.\n"
          f"Panel does NOT use it yet. Diff it against {a.policy}, review it, and deploy it yourself.")
    return 0


def cmd_learn(a):
    """Review learned patterns: mark each a real threat or a false positive. Threats become rule suggestions; false positives loosen anomaly thresholds."""
    from panel_firewall.firewall import learn
    led = _ledger(a)
    who = a.who or getpass.getuser()
    if a.mark is not None:
        print(learn.mark(led, a.mark, a.as_, who))
        return 0
    todo = learn.patterns(led, status="unconfirmed")
    if a.list or not todo or not sys.stdin.isatty():
        if not todo:
            print("No unconfirmed patterns.")
        for p in todo:
            h = learn.hints(led, p["tool"])
            print(learn.describe(p) + (f"   (earlier holds of this tool: {h['approved']} approved, {h['denied']} denied)" if h["approved"] or h["denied"] else ""))
        if todo and not a.list:
            print("\nRun in a terminal to review them, or: usepanel learn --mark ID --as threat|false_positive")
        return 0
    for p in todo:
        h = learn.hints(led, p["tool"])
        print(learn.describe(p) + (f"\n    hint: earlier holds of this tool: {h['approved']} approved, {h['denied']} denied" if h["approved"] or h["denied"] else ""))
        while True:
            c = input("  mark as [t]hreat / [f]alse positive / [s]kip: ").strip().lower()
            if c[:1] in ("t", "f", "s"):
                break
        if c[0] != "s":
            print("  " + learn.mark(led, p["id"], "threat" if c[0] == "t" else "false_positive", who))
    return 0


def cmd_baseline(a):
    from panel_firewall.firewall import anomaly
    from panel_firewall.firewall.policy import load_policy
    led = _ledger(a)
    if a.rebuild:
        counts = anomaly.rebuild(load_policy(a.policy) if a.policy else None, led, time.time())
        print("rebuilt baselines from the ledger: " + (", ".join(f"{t} ({n} calls)" for t, n in sorted(counts.items())) or "no executed calls found"))
    print(anomaly.format_baselines(led))
    return 0


def cmd_tighten(a):
    """Repeat observe -> suggest -> test until nothing more can be caught without a false positive. Writes <policy>.suggested.yaml only."""
    from panel_firewall.firewall import tighten
    from panel_firewall.firewall.policy import load_policy
    pol = load_policy(a.policy)
    res = tighten.run(_ledger(a), pol.raw, max_rounds=a.max_rounds, n_history=a.history, min_calls=a.min_calls, min_severity=a.min_severity,
                      min_headroom=a.min_headroom)
    if res["stop"] in ("no history", "nothing to tighten"):
        print("No requested actions in the ledger." if res["stop"] == "no history" else
              f"Nothing to tighten: {res['anomalies']} anomalies among the last {res['history']} actions, none uncaught.")
        return 0
    n = len(res["accepted"])
    if res["stop"] == "max_rounds":
        print(f"Stopped at --max-rounds {a.max_rounds}; rules were still being added (run again to continue).")
    if n:
        out = tighten.write_staging(a.policy, res["staged"], res["accepted"], a.out)
        print(f"Tightening complete. {n} new rule{'s' if n != 1 else ''} staged in {out}\nThe live policy was not changed. Diff, review, then merge it yourself.")
    else:
        print("Tightening complete. 0 new rules staged.")
    return 0


def cmd_exploits(a):
    """What exploit patterns this machine has seen (anonymized signatures stored by `telemetry: true`)."""
    from panel_firewall.firewall import telemetry
    sigs = telemetry.ExploitLog(_ledger(a)).since(_since(a))
    if a.json:
        print(json.dumps([s.to_dict() for s in sigs], indent=2))
    else:
        print(telemetry.format_summary(telemetry.summarize(sigs), a.since or ""))
    return 0


def cmd_threats(a):
    print("Threat feed requires Panel Cloud. Run with --cloud-url to connect.")
    return 0


def cmd_export_log(a):
    from panel_firewall.firewall.policy import load_policy
    from panel_firewall.firewall.summary import export_log
    rows = export_log(_ledger(a), _since(a), a.include_raw_args, load_policy(a.policy) if a.policy else None)
    Path(a.out).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
    print(f"wrote {len(rows)} events to {a.out} (PII-scrubbed summaries; " +
          ("RAW ARGUMENTS INCLUDED, unscrubbed" if a.include_raw_args else "no raw arguments") + ")")
    return 0


def cmd_ui(a):
    from panel_firewall.firewall.pin import PinStore
    from panel_firewall.firewall.ui import serve_forever
    serve_forever(_ledger(a), a.port, a.who, PinStore(a.pin_file))
    return 0


def cmd_verify(a):
    from panel_firewall.firewall.receipts import load_public_key, verify_receipt
    r = json.loads(Path(a.file).read_text())
    problems = verify_receipt(r, load_public_key(a.pubkey), a.policy)
    if problems:
        print("INVALID: " + "; ".join(problems))
        return 1
    why = {x.split("=", 1)[0]: x.split("=", 1)[1] for x in r["reasons"] if "=" in x}
    print(f"VALID signature and hashes. Panel decided '{r['verdict']}' (outcome: {why.get('outcome')}) for {why.get('tool')} "
          f"under policy v{why.get('policy_version')} ({r['policy_sha256'][:12]}...).")
    if "mode=shadow" in r["reasons"]:
        print("SHADOW MODE receipt: Panel recorded this verdict but did NOT enforce it; the action was allowed to run.")
    print("This proves what Panel checked and decided, and that the record was not altered. It does NOT prove the action was safe.")
    return 0


def cmd_verify_chain(a):
    from panel_firewall.firewall.receipts import load_public_key, verify_chain
    led = _ledger(a)
    res = verify_chain(led.receipts(), load_public_key(a.pubkey) if a.pubkey else None, a.expect_head, a.expect_count)
    for m in res.errors:
        print("FAIL:", m)
    if res.ok:
        print(f"OK: {res.count} receipts, chain intact, head {res.head}")
    for m in res.notes:
        print("note:", m)
    return 0 if res.ok else 1


def cmd_export(a):
    out = _ledger(a).receipts()
    if a.scrub:
        from panel_firewall.firewall.scrub import scrub
        out = [dict(scrub(r), scrubbed=True) for r in out]       # signatures and the chain no longer verify on a scrubbed copy
    Path(a.out).write_text(json.dumps(out, indent=2))
    print(f"wrote {len(out)} receipts to {a.out}")
    return 0


def cmd_check_reply(a):
    from panel_firewall.firewall.claims import check_reply
    from panel_firewall.firewall.policy import load_policy
    r = check_reply(a.text, _ledger(a), a.conversation, load_policy(a.policy) if a.policy else None, mode=a.mode)
    print(json.dumps({"ok": r.ok, "reply": r.reply, "claims": [c.__dict__ for c in r.claims]}, indent=2))
    return 0 if r.ok else 1


def cmd_init(a):
    from panel_firewall.firewall.init import run_init
    return run_init(a)


def cmd_proxy(a):
    from panel_firewall.firewall.gateway import run_proxy
    return run_proxy(a)


def cmd_audit(a):
    from panel_firewall.firewall.audit import run_audit
    return run_audit(a)


def cmd_doctor(a):
    from panel_firewall.firewall.doctor import cmd_doctor as run
    return run(a)


def cmd_serve(a):
    from panel_firewall.firewall.gateway import run_serve
    return run_serve(a)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="usepanel", description="Action firewall for AI agents")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, policy=True):
        if policy:
            p.add_argument("--policy", help="policy file (YAML)")
        p.add_argument("--ledger", help="ledger SQLite path (default: next to the policy)")

    def cloud_flags(p):
        p.add_argument("--cloud-url", help="Panel Cloud API URL: take the signed policy from the cloud, report data-minimised events, accept cloud approvals "
                       "(default: the one saved by `usepanel init --token`, when no --policy is given)")
        p.add_argument("--api-key", help="workspace API key, overrides the saved one (visible in the process list; prefer --api-key-file or PANEL_API_KEY)")
        p.add_argument("--api-key-file", help="file containing the workspace API key")
        p.add_argument("--cloud-pubkey", help="pin the cloud's Ed25519 policy-signing key (base64) instead of trusting the first one seen")
        p.add_argument("--cloud-state-dir", help="where the cached signed policy, pinned key and upload cursor live (default ~/.config/panel/cloud/<id>)")

    p = sub.add_parser("demo", help="zero-setup demo: a simulated agent tries five actions and Panel blocks, holds and approves them (no config, no API keys)")
    p.add_argument("--no-color", action="store_true"); p.set_defaults(fn=cmd_demo)
    p = sub.add_parser("keygen", help="create the Ed25519 receipt-signing key (outside the repo)")
    p.add_argument("--path"); p.add_argument("--force", action="store_true"); p.set_defaults(fn=cmd_keygen)
    p = sub.add_parser("fingerprint", help="show the fingerprint of the receipt-signing key, to compare with Panel Cloud before confirming it")
    p.add_argument("--key"); p.set_defaults(fn=cmd_fingerprint)
    p = sub.add_parser("pin", help="set or check the approval PIN (typed at the terminal only)")
    p.add_argument("action", choices=["set", "status"]); p.add_argument("--pin-file"); p.set_defaults(fn=cmd_pin)
    p = sub.add_parser("pending", help="list actions waiting for approval"); common(p); p.set_defaults(fn=cmd_pending)
    for name, deny in (("approve", False), ("deny", True)):
        p = sub.add_parser(name, help=f"{name} a held action (the only way consent is granted, besides `usepanel ui`)")
        p.add_argument("id"); p.add_argument("--who"); p.add_argument("--reason"); p.add_argument("--pin-file"); common(p)
        p.set_defaults(fn=lambda a, d=deny: _decide(a, d))
    p = sub.add_parser("unfreeze", help="lift a circuit-breaker freeze (needs the approval PIN)"); common(p)
    p.add_argument("--who"); p.add_argument("--pin-file"); p.add_argument("--key"); p.set_defaults(fn=cmd_unfreeze)
    p = sub.add_parser("ui", help="local approval UI on 127.0.0.1"); common(p); p.add_argument("--port", type=int, default=8765); p.add_argument("--pin-file")
    p.add_argument("--who"); p.set_defaults(fn=cmd_ui)
    p = sub.add_parser("verify-receipt", help="check a receipt's signature and hashes")
    p.add_argument("file"); p.add_argument("--pubkey", required=True, help="public key (.pub) or private key file")
    p.add_argument("--policy", help="policy file to compare against the receipt's policy hash"); p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("verify-chain", help="check the ledger's receipt chain (deleted/edited/reordered receipts)")
    common(p); p.add_argument("--pubkey"); p.add_argument("--expect-head"); p.add_argument("--expect-count", type=int)
    p.set_defaults(fn=cmd_verify_chain)
    p = sub.add_parser("export-receipts"); common(p); p.add_argument("--out", required=True)
    p.add_argument("--scrub", action="store_true", help="mask emails/phones/cards/keys in the reasons (the copy will no longer verify)")
    p.set_defaults(fn=cmd_export)
    p = sub.add_parser("report", help="shadow mode: what would have been blocked or held, by rule")
    common(p); p.add_argument("--since", default="48h"); p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_report)
    p = sub.add_parser("suggest", help="suggest policy rules from observed (shadow-mode) traffic; accepted rules go to a proposal file, never the live policy")
    common(p); p.add_argument("--since", default="7d"); p.add_argument("--from-shadow", action="store_true", help="only calls that ran while in shadow mode")
    p.add_argument("--min-calls", type=int, default=100, help="a tool needs this many executed calls before anything is suggested (default 100)")
    p.add_argument("--accept", choices=("all", "review", "skip"), help="answer the prompt without a terminal; `all` writes every suggestion to the proposal file")
    p.add_argument("--out", help="proposal file (default <policy>.suggested.yaml)"); p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_suggest)
    p = sub.add_parser("learn", help="mark learned patterns as real threats or false positives (threats become rule suggestions)")
    common(p); p.add_argument("--list", action="store_true"); p.add_argument("--mark", type=int, metavar="ID")
    p.add_argument("--as", dest="as_", choices=("threat", "false_positive")); p.add_argument("--who"); p.set_defaults(fn=cmd_learn)
    p = sub.add_parser("baseline", help="show the learned per-tool baselines (amount percentiles, call rate); --rebuild recomputes them from the ledger")
    common(p); p.add_argument("--rebuild", action="store_true"); p.set_defaults(fn=cmd_baseline)
    p = sub.add_parser("tighten", help="loop observe -> suggest -> test: stage rules that catch anomalies with zero false positives (never edits the live policy)")
    common(p); p.add_argument("--max-rounds", type=int, default=10); p.add_argument("--history", type=int, default=500, help="how many recent actions to replay (default 500)")
    p.add_argument("--min-calls", type=int, default=100); p.add_argument("--min-severity", type=float, default=0.4)
    p.add_argument("--min-headroom", type=float, default=1.02, help="never tighten a threshold below this multiple of the largest legitimate value (default 1.02)")
    p.add_argument("--out", help="staging file (default <policy>.suggested.yaml)"); p.set_defaults(fn=cmd_tighten)
    p = sub.add_parser("exploits", help="anonymized exploit patterns seen on this machine (needs `telemetry: true` in the policy to record them)")
    common(p); p.add_argument("--since", default="24h"); p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_exploits)
    p = sub.add_parser("threats", help="the aggregated threat feed from Panel Cloud (placeholder)")
    cloud_flags(p); p.set_defaults(fn=cmd_threats)
    p = sub.add_parser("export-log", help="PII-scrubbed event summaries (JSONL). No raw arguments unless --include-raw-args")
    common(p); p.add_argument("--out", required=True); p.add_argument("--since"); p.add_argument("--include-raw-args", action="store_true")
    p.set_defaults(fn=cmd_export_log)
    p = sub.add_parser("check-reply", help="would this agent reply be blocked as an unbacked 'it's done' claim?")
    common(p); p.add_argument("--conversation", default="default"); p.add_argument("--mode", choices=["receipts", "regex"], default="receipts"); p.add_argument("text"); p.set_defaults(fn=cmd_check_reply)
    p = sub.add_parser("init", help="connect Panel Cloud (--cloud, in the browser; or --token, from the dashboard), or inspect an upstream MCP server and write a starter policy to review")
    p.add_argument("--token", help="one-time setup token from the Panel Cloud dashboard (pit_...): fetches and saves this workspace's API key")
    p.add_argument("--cloud", action="store_true", help="connect Panel Cloud by authorising this machine in your browser (no key to copy)")
    p.add_argument("--cloud-url", help="Panel Cloud URL for --cloud or --token (default https://app.usepanel.dev)")
    p.add_argument("--out", default="panel-policy.yaml"); p.add_argument("--force", action="store_true")
    p.add_argument("upstream", nargs=argparse.REMAINDER, help="-- <upstream command>"); p.set_defaults(fn=cmd_init)
    p = sub.add_parser("proxy", help="wrap an existing MCP server: usepanel proxy --policy p.yaml -- <upstream cmd>")
    common(p); p.add_argument("--key"); p.add_argument("--session", default="default")
    p.add_argument("--shadow", action="store_true", help="evaluate everything and log what WOULD be blocked/held, but let actions run")
    cloud_flags(p)
    p.add_argument("upstream", nargs=argparse.REMAINDER); p.set_defaults(fn=cmd_proxy)
    p = sub.add_parser("audit", help="inspect MCP tool definitions and draft a policy (no keys, PIN or config needed)")
    p.add_argument("--policy", help="optional policy to check for missing controls")
    p.add_argument("--out", help="write starter YAML instead of printing it (must not exist)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("upstream", nargs=argparse.REMAINDER, help="-- <upstream command>"); p.set_defaults(fn=cmd_audit)
    p = sub.add_parser("doctor", help="check your setup (signing key, PIN, API key, cloud reachability) and print the fix for each problem")
    p.add_argument("--policy"); p.add_argument("--key"); p.add_argument("--pin-file"); cloud_flags(p)
    p.add_argument("upstream", nargs=argparse.REMAINDER, help="-- <upstream command> (optional: checks it is installed)"); p.set_defaults(fn=cmd_doctor)
    p = sub.add_parser("serve", help="serve the policy's native connectors (sqlite/stripe/shopify) as an MCP server")
    common(p); p.add_argument("--key"); p.add_argument("--session", default="default")
    p.add_argument("--shadow", action="store_true", help="shadow mode (see proxy --shadow)"); cloud_flags(p); p.set_defaults(fn=cmd_serve)
    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except UpstreamError as e:
        print(str(e), file=sys.stderr)
        return 1
    except FirewallError as e:
        print(f"panel: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:        # Ctrl+C is how a person stops `usepanel proxy` / `serve`: not an error. stderr, because stdout is the MCP stream
        print("Panel stopped.", file=sys.stderr)
        return 0
