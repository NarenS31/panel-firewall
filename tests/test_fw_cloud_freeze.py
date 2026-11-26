"""A Panel Cloud 'unfreeze' decision: applied only when signed, for THIS freeze, unexpired and single-use."""
import json
import time

import httpx
import pytest
from tenthlook_core import receipt as core

from panel_firewall.firewall.cloud import (
    CloudClient,
    CloudState,
    CloudSync,
    PolicyManager,
)
from panel_firewall.firewall.engine import Firewall
from panel_firewall.firewall.ledger import Ledger
from panel_firewall.firewall.policy import parse_policy
from tests.fw_helpers import POLICY_SHA, FakeConnector, act, signer
from tests.test_fw_cloud import FakeCloud, b64


@pytest.fixture
def rig(tmp_path):
    cloud = FakeCloud(); cloud.unfreeze = None
    orig = cloud.handler
    def handler(req):
        if req.url.path == "/v1/proxy/freeze":
            return httpx.Response(200, json={"frozen": True, "unfreeze": cloud.unfreeze})
        return orig(req)
    state = CloudState("https://cloud.test", "pcl_key_for_tests_0000", tmp_path / "s")
    client = CloudClient("https://cloud.test", "pcl_key_for_tests_0000", transport=httpx.MockTransport(handler))
    pm = PolicyManager(client, state); pm.bootstrap()
    pol = parse_policy({"version": "t", "mode": "auto", "actions": {"fake.pay": {"max_amount": 100}, "fake.read": {"risk": "read"}}, "circuit_breaker": {}}, POLICY_SHA)
    fw = Firewall(pol, Ledger(":memory:"), signer(), [FakeConnector()])
    sync = CloudSync(client, state, pm, fw)
    sync.apply_policy = lambda p: None
    return cloud, fw, sync


def trip(fw):
    for i in range(3): fw.handle(act(amount=500 + i))
    assert fw.frozen() is not None
    return core.receipt_hash([r for r in fw.ledger.receipts() if "outcome=frozen" in r["reasons"]][-1])


def decision(cloud, freeze_hash, **over):
    d = {"type": "unfreeze", "workspace_id": cloud.ws, "freeze_receipt_sha256": freeze_hash, "decided_by": "usr_1", "decided_at": int(time.time()),
         "expires_at": int(time.time()) + 300, "nonce": "n" + str(time.time_ns()), **over}
    text = json.dumps(d)
    return {"decision": text, "signature": b64(cloud.sk.sign(text.encode()))}


def test_a_valid_signed_unfreeze_lifts_the_freeze_once(rig):
    cloud, fw, sync = rig
    h = trip(fw); cloud.unfreeze = decision(cloud, h)
    assert sync.check_unfreeze() is True and fw.frozen() is None
    assert fw.handle(act(amount=10)).status == "executed"
    assert any("outcome=unfrozen" in r["reasons"] for r in fw.ledger.receipts())
    unfroze = [e for e in fw.ledger.events(limit=10**6) if e["event"] == "unfreeze"][0]["data"]
    assert unfroze["who"] == "cloud:usr_1" and unfroze["cloud_nonce"]


@pytest.mark.parametrize("mutate,label", [
    (lambda c, h: decision(c, "f" * 64), "other freeze"),
    (lambda c, h: decision(c, h, expires_at=int(time.time()) - 5), "expired"),
    (lambda c, h: decision(c, h, workspace_id="ws_other"), "other workspace"),
    (lambda c, h: decision(c, h, type="decision"), "wrong type"),
    (lambda c, h: {**decision(c, h), "signature": b64(b"\0" * 64)}, "bad signature"),
])
def test_bad_unfreeze_decisions_are_ignored(rig, mutate, label):
    cloud, fw, sync = rig
    h = trip(fw); cloud.unfreeze = mutate(cloud, h)
    assert sync.check_unfreeze() is False and fw.frozen() is not None, label


def test_a_replayed_unfreeze_cannot_lift_a_later_freeze(rig):
    cloud, fw, sync = rig
    h = trip(fw); d = decision(cloud, h); cloud.unfreeze = d
    assert sync.check_unfreeze()
    time.sleep(0.01)
    h2 = trip(fw)                                     # frozen again (new freeze receipt)
    assert h2 != h and sync.check_unfreeze() is False and fw.frozen() is not None


def test_nothing_happens_when_not_frozen_or_cloud_down(rig):
    cloud, fw, sync = rig
    assert sync.check_unfreeze() is False
    trip(fw); cloud.down = True
    assert sync.check_unfreeze() is False and fw.frozen() is not None
