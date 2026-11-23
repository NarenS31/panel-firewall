"""Panel Cloud client: signed policy (pinned key, hash, rollback, cache re-verification), offline behaviour, data-minimised uploads,
signed approval decisions (bound to the exact action, single use, expiring). Uses a fake cloud that really signs with Ed25519."""
import base64
import hashlib
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from panel_firewall.firewall.cloud import CloudClient, CloudError, CloudState, CloudSync, PolicyManager, receipt_event
from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from panel_firewall.firewall.policy import load_policy
from tests.fw_helpers import FakeConnector, act, signer

WS = "ws_test_000001"


def b64(b): return base64.b64encode(b).decode()


class FakeCloud:
    """Just enough of the Panel Cloud /v1 API, signing with a real Ed25519 key."""
    def __init__(self, ws=WS):
        self.sk = Ed25519PrivateKey.generate()
        self.pub = b64(self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.ws, self.version, self.mode, self.down = ws, 1, "shadow", False
        self.events, self.approvals, self.posted_bodies = [], {}, []
        self.fail_events = 0

    def policy_doc(self):
        enf = {"fake.pay": {"risk": "write", "max_amount": 100, "consent_over_amount": 50}, "fake.read": {"risk": "read"}}
        return json.dumps({"version": str(self.version), "mode": "shadow" if self.mode == "shadow" else "auto", "enforce_mode": "auto", "reviewed": True,
                           "actions": enf}, sort_keys=True, separators=(",", ":"))

    def bundle(self, **over):
        text = over.pop("policy_json", None) or self.policy_doc()
        env = {"type": "policy", "workspace_id": self.ws, "version": self.version, "mode": self.mode, "policy_sha256": hashlib.sha256(text.encode()).hexdigest(),
               "issued_at": int(time.time()), "key_id": self.pub[:12], **over.pop("env", {})}
        es = json.dumps(env)
        return {"envelope": es, "signature": b64(self.sk.sign(es.encode())), "policy_json": text, "public_key": self.pub, **over}

    def decision(self, approval_id, action_sha, decision="approve", **over):
        d = {"type": "decision", "workspace_id": self.ws, "approval_id": approval_id, "action_sha256": action_sha, "decision": decision,
             "decided_by": "usr_1", "decided_at": int(time.time()), "expires_at": int(time.time()) + 300, "nonce": "n-" + approval_id + str(time.time_ns()), **over}
        s = json.dumps(d)
        return {"id": approval_id, "status": "approved" if decision == "approve" else "denied", "action_sha256": action_sha, "decision": s, "signature": b64(self.sk.sign(s.encode()))}

    def handler(self, req: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("down")
        path = req.url.path
        if path == "/v1/policy":
            return httpx.Response(200, json=self.bundle())
        if path == "/v1/events":
            body = json.loads(req.content); self.posted_bodies.append(body)
            if self.fail_events:
                self.fail_events -= 1; return httpx.Response(503, json={"error": "busy"})
            self.events += body["events"]; return httpx.Response(202, json={"accepted": len(body["events"])})
        if path == "/v1/approvals" and req.method == "POST":
            b = json.loads(req.content); self.posted_bodies.append(b); self.approvals[b["approval_id"]] = {"req": b, "reply": None}
            return httpx.Response(201, json={"id": b["approval_id"], "status": "pending"})
        if path.startswith("/v1/approvals/"):
            a = self.approvals.get(path.rsplit("/", 1)[1])
            if not a: return httpx.Response(404, json={"error": "no such approval"})
            return httpx.Response(200, json=a["reply"] or {"id": path.rsplit("/", 1)[1], "status": "pending"})
        return httpx.Response(404, json={"error": "not found"})


@pytest.fixture
def rig(tmp_path):
    cloud = FakeCloud()
    state = CloudState("https://cloud.test", "pcl_key_for_tests_0000", tmp_path / "state")
    client = CloudClient("https://cloud.test", "pcl_key_for_tests_0000", transport=httpx.MockTransport(cloud.handler))
    pm = PolicyManager(client, state)
    return cloud, state, client, pm


def make_fw(pm, led=None):
    return Firewall(pm.policy, led or Ledger(":memory:"), signer(), [FakeConnector()], mode=pm.policy.mode)


# ------------------------------------------------------------------------------------------------ signed policy
def test_first_contact_pins_the_key_and_writes_the_exact_signed_bytes(rig):
    cloud, state, _, pm = rig
    pol = pm.bootstrap()
    assert state.pinned() == {"public_key": cloud.pub, "workspace_id": WS}
    text = cloud.policy_doc()
    assert state.policy_file.read_bytes() == text.encode()
    assert pol.sha256 == hashlib.sha256(text.encode()).hexdigest() and pol.mode == "shadow" and pol.version == "1"
    assert oct(state.policy_file.stat().st_mode & 0o777) == "0o600"


def test_policy_with_a_bad_signature_or_wrong_hash_is_refused(rig):
    cloud, state, client, pm = rig
    pm.bootstrap()
    orig = cloud.handler
    for mutate in (lambda b: b.update(policy_json=b["policy_json"].replace('"max_amount":100', '"max_amount":9999')),
                   lambda b: b.update(signature=b64(b"\0" * 64)),
                   lambda b: b.update(envelope=b["envelope"].replace('"version": 1', '"version": 2'))):
        def h(req, m=mutate):
            r = orig(req)
            if req.url.path == "/v1/policy":
                b = r.json(); m(b); return httpx.Response(200, json=b)
            return r
        pm2 = PolicyManager(CloudClient("https://cloud.test", "k", transport=httpx.MockTransport(h)), state)
        with pytest.raises(CloudError, match="INVALID|does not match"):
            pm2.refresh()


def test_a_different_signing_key_after_pinning_is_refused(rig):
    cloud, state, client, pm = rig
    pm.bootstrap()
    impostor = FakeCloud()
    pm2 = PolicyManager(CloudClient("https://cloud.test", "k", transport=httpx.MockTransport(impostor.handler)), state)
    with pytest.raises(CloudError, match="does not match the pinned key"):
        pm2.refresh()
    # an explicit --cloud-pubkey beats trust-on-first-use
    fresh = CloudState("https://cloud.test", "other-key-000000000", state.dir.parent / "state2")
    pm3 = PolicyManager(CloudClient("https://cloud.test", "k", transport=httpx.MockTransport(impostor.handler)), fresh, pubkey=cloud.pub)
    with pytest.raises(CloudError, match="does not match the pinned key"):
        pm3.refresh()


def test_policy_for_another_workspace_and_rollbacks_are_refused(rig):
    cloud, state, client, pm = rig
    cloud.version = 5
    pm.bootstrap()
    cloud.version = 3                                           # a replayed older (validly signed) policy
    with pytest.raises(CloudError, match="backwards"):
        pm.refresh()
    other = FakeCloud(ws="ws_other_000001"); other.sk, other.pub = cloud.sk, cloud.pub
    pm2 = PolicyManager(CloudClient("https://cloud.test", "k", transport=httpx.MockTransport(other.handler)), state)
    with pytest.raises(CloudError, match="different workspace"):
        pm2.refresh()


def test_policy_the_engine_rejects_is_refused_even_if_signed(rig):
    cloud, state, client, pm = rig
    bad = json.dumps({"version": "9", "mode": "auto", "actions": {"x": {"max_ammount": 1}}})
    orig = cloud.handler
    cloud.policy_doc = lambda: bad
    with pytest.raises(Exception, match="unknown keys"):
        pm.bootstrap()


def test_cloud_down_uses_the_cached_signed_policy_and_keeps_enforcing(rig):
    cloud, state, client, pm = rig
    cloud.mode = "enforce"
    pm.bootstrap()
    cloud.down = True
    pm2 = PolicyManager(client, state)
    pol = pm2.bootstrap()
    assert pol.mode == "auto" and pm2.version == 1
    fw = make_fw(pm2)
    assert fw.handle(act(amount=500)).status == "blocked"              # still enforced with the cloud unreachable
    assert fw.handle(act(amount=10)).status == "executed"


def test_cloud_down_with_no_cache_refuses_to_start(rig):
    cloud, state, client, pm = rig
    cloud.down = True
    with pytest.raises(CloudError, match="will not start"):
        pm.bootstrap()


def test_a_tampered_cache_is_rejected_on_load(rig):
    cloud, state, client, pm = rig
    cloud.mode = "enforce"
    pm.bootstrap()
    b = json.loads(state.bundle_file.read_text())
    b["policy_json"] = b["policy_json"].replace('"max_amount":100', '"max_amount":100000')       # an agent loosens the cache
    state.bundle_file.write_text(json.dumps(b))
    cloud.down = True
    with pytest.raises(CloudError, match="will not start"):
        PolicyManager(client, state).bootstrap()
    # editing the policy FILE (not the bundle) changes nothing either: the file is rewritten from the verified bundle
    state.bundle_file.write_text(json.dumps(cloud.bundle())); state.policy_file.write_text('{"mode":"auto","actions":{"fake.pay":{}}}')
    pol = PolicyManager(client, state).bootstrap()
    assert pol.rule_for("fake.pay").get("max_amount") == 100


# ------------------------------------------------------------------------------------------------ live changes
def test_cloud_enforcement_toggle_reaches_the_running_firewall_but_local_shadow_flag_wins(rig):
    cloud, state, client, pm = rig
    pm.bootstrap()
    fw = make_fw(pm)
    sync = CloudSync(client, state, pm, fw, policy_every=0)
    sync.apply_policy(pm.policy)
    assert fw.mode == "shadow" and fw.handle(act(amount=500)).status == "executed"          # shadow lets it through
    cloud.version, cloud.mode = 2, "enforce"
    assert sync.refresh_policy() and fw.mode == "auto"
    assert fw.handle(act(amount=501)).status == "blocked"
    forced = CloudSync(client, state, pm, fw, forced_shadow=True, policy_every=0)
    forced.apply_policy(pm.policy)
    assert fw.mode == "shadow"


# ------------------------------------------------------------------------------------------------ events
def test_events_are_data_minimised_and_cursor_based(rig):
    cloud, state, client, pm = rig
    pm.bootstrap()
    fw = make_fw(pm)
    sync = CloudSync(client, state, pm, fw)
    sync.apply_policy(pm.policy)
    fw.handle(act(amount=500, note="refund jane@example.com card 4242 4242 4242 4242"))      # shadow: runs, would be blocked
    fw.handle(act("fake.read"))
    assert sync.upload_events() == 2
    posted = json.dumps(cloud.posted_bodies)
    for leak in ("jane@example.com", "4242 4242", "note", "args", "refund jane"):
        assert leak not in posted
    e = cloud.events[0]
    assert e["tool"] == "fake.pay" and e["verdict"] == "block" and e["mode"] == "shadow" and e["shadow_would"] == "block"
    assert e["rule"] == "max_amount" and e["amount"] == 500.0 and "would have been BLOCKED" in e["summary"]
    assert len(e["receipt_sha256"]) == 64 and len(e["action_sha256"]) == 64 and e["policy_sha256"] == pm.policy.sha256
    assert set(e) <= {"id", "ts", "tool", "verdict", "outcome", "mode", "shadow_would", "rule", "amount", "summary", "action_sha256", "receipt_sha256", "policy_sha256", "receipt"}
    assert e["receipt"]["signature"] and e["receipt"]["artifact_sha256"] == e["action_sha256"]
    from tenthlook_core import receipt as core_receipt
    assert core_receipt.verify(e["receipt"]).ok and core_receipt.receipt_hash(e["receipt"]) == e["receipt_sha256"]
    assert sync.upload_events() == 0                                  # cursor moved: nothing re-sent


def test_failed_uploads_are_retried_without_loss_or_duplicates(rig):
    cloud, state, client, pm = rig
    pm.bootstrap()
    fw = make_fw(pm)
    sync = CloudSync(client, state, pm, fw)
    sync.apply_policy(pm.policy)
    for amt in (1, 2, 3):
        fw.handle(act(amount=amt, key=f"k{amt}"))
    cloud.fail_events = 1
    assert sync.upload_events() == 0 and not sync.online
    assert cloud.events == []
    assert sync.upload_events() == 3
    ids = [e["id"] for e in cloud.events]
    assert len(set(ids)) == 3 and all(i.startswith(state.cursor()["ledger_id"]) for i in ids)
    cloud.down = True
    fw.handle(act(amount=4, key="k4"))
    assert sync.upload_events() == 0
    cloud.down = False
    assert sync.upload_events() == 1


def test_receipt_event_for_an_enforced_block_has_rule_and_no_shadow_flag(rig):
    cloud, state, client, pm = rig
    cloud.mode = "enforce"
    pm.bootstrap()
    fw = make_fw(pm)
    o = fw.handle(act(amount=500))
    ev = receipt_event("L", 1, o.receipt, fw.ledger.receipt_details()[0], pm.policy)
    assert ev["verdict"] == "block" and ev["outcome"] == "blocked" and ev["mode"] == "enforce" and ev["rule"] == "max_amount" and "shadow_would" not in ev


# ------------------------------------------------------------------------------------------------ approvals
def enforcing(rig):
    cloud, state, client, pm = rig
    cloud.mode = "enforce"
    pm.bootstrap()
    fw = make_fw(pm)
    sync = CloudSync(client, state, pm, fw)
    sync.apply_policy(pm.policy)
    return cloud, state, client, pm, fw, sync


def test_held_action_is_registered_and_a_valid_signed_approval_releases_it_once(rig):
    cloud, state, client, pm, fw, sync = enforcing(rig)
    o = fw.handle(act(amount=75))
    assert o.status == "needs_consent"
    assert sync.register_pending() == 1
    req = cloud.approvals[o.approval_id]["req"]
    assert req["action_sha256"] == fw.ledger.pending()[0]["action_sha"] and req["amount"] == 75 and "args" not in req
    assert sync.register_pending() == 0                                # already registered
    pend = fw.ledger.pending()[0]
    cloud.approvals[o.approval_id]["reply"] = cloud.decision(o.approval_id, pend["action_sha"])
    assert sync.check_decisions() == 1
    ev = [e for e in fw.ledger.events() if e["event"] == "approved"][0]["data"]
    assert ev["who"] == "cloud:usr_1" and ev["cloud_nonce"] and ev["action_sha"] == pend["action_sha"]
    assert fw.handle(act(amount=75)).status == "executed"
    assert fw.handle(act(amount=75)).status == "replayed"


def test_decision_with_bad_signature_wrong_action_expired_or_replayed_is_ignored(rig):
    cloud, state, client, pm, fw, sync = enforcing(rig)
    o = fw.handle(act(amount=75)); sync.register_pending()
    sha = fw.ledger.pending()[0]["action_sha"]
    good = cloud.decision(o.approval_id, sha)
    forged = dict(good, signature=b64(b"\1" * 64))
    other_key = FakeCloud(); signed_by_other = other_key.decision(o.approval_id, sha)
    cases = {"bad signature": forged, "unpinned key": signed_by_other,
             "different action": cloud.decision(o.approval_id, "0" * 64),
             "different approval id": cloud.decision("zzzzzzzzzz", sha),
             "expired": cloud.decision(o.approval_id, sha, expires_at=int(time.time()) - 5),
             "other workspace": cloud.decision(o.approval_id, sha, workspace_id="ws_evil"),
             "not a decision": cloud.decision(o.approval_id, sha, type="policy")}
    for name, reply in cases.items():
        cloud.approvals[o.approval_id]["reply"] = reply
        assert sync.check_decisions() == 0, name
        assert fw.ledger.consent_state(o.idempotency_key) == "pending", name
        assert fw.handle(act(amount=75)).status == "needs_consent", name
    cloud.approvals[o.approval_id]["reply"] = good
    assert sync.check_decisions() == 1
    # replaying the same signed decision for a NEW pending action with the same id is refused (nonce already used)
    assert state.nonce_used(json.loads(good["decision"])["nonce"])
    assert not sync.apply_decision(o.approval_id, {"action_sha": sha}, good)


def test_cloud_denial_blocks_the_action(rig):
    cloud, state, client, pm, fw, sync = enforcing(rig)
    o = fw.handle(act(amount=75)); sync.register_pending()
    cloud.approvals[o.approval_id]["reply"] = cloud.decision(o.approval_id, fw.ledger.pending()[0]["action_sha"], "deny")
    assert sync.check_decisions() == 1
    assert fw.handle(act(amount=75)).status == "blocked"


def test_offline_held_actions_stay_held_and_nothing_is_auto_approved(rig):
    cloud, state, client, pm, fw, sync = enforcing(rig)
    cloud.down = True
    o = fw.handle(act(amount=75))
    assert o.status == "needs_consent"
    assert sync.register_pending() == 0 and not sync.online
    for _ in range(3):
        assert fw.handle(act(amount=75)).status == "needs_consent"          # still held, however long the outage lasts
    assert fw.handle(act(amount=500)).status == "blocked"                    # and the cached policy still blocks
    cloud.down = False
    assert sync.register_pending() == 1                                      # registered as soon as the cloud returns
    assert fw.handle(act(amount=75)).status == "needs_consent"


def test_decisions_picked_up_after_an_outage_and_local_pin_approval_still_works(rig):
    cloud, state, client, pm, fw, sync = enforcing(rig)
    o = fw.handle(act(amount=75)); sync.register_pending()
    cloud.down = True
    assert sync.check_decisions() == 0
    cloud.down = False
    cloud.approvals[o.approval_id]["reply"] = cloud.decision(o.approval_id, fw.ledger.pending()[0]["action_sha"])
    assert sync.check_decisions() == 1
    # a locally decided approval stops being tracked
    o2 = fw.handle(act(amount=77)); sync.register_pending()
    assert fw.ledger.approve(o2.approval_id, "local human")[0]
    sync.check_decisions()
    assert o2.approval_id not in sync._registered
