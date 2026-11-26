"""`usepanel init --cloud`: browser authorisation. The CLI opens /authorize with a challenge, polls with the verifier, saves the key."""
import argparse
import hashlib
import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from panel_firewall.firewall import cloud
from panel_firewall.firewall.cli import main
from panel_firewall.firewall.init import run_cloud_browser_init
from panel_firewall.firewall.types import FirewallError

KEY = "pcl_" + "b" * 30
OK = {"api_key": KEY, "workspace": {"id": "ws_acme", "name": "Acme"}, "key_id": "key_7"}


@pytest.fixture
def cfg_dir(tmp_path, monkeypatch):
    d = tmp_path / "cfg" / "usepanel"
    monkeypatch.setenv("PANEL_CONFIG_DIR", str(d))
    return d


def cloud_that(pending=2, final=(200, OK)):
    """A fake Worker: 202 `pending` times, then `final`. Records what the CLI sent and checks the verifier matches the URL's challenge."""
    seen = {"posts": [], "url": None}

    def handler(req):
        body = json.loads(req.content)
        seen["posts"].append(body)
        assert req.url.path == "/v1/proxy/cli-auth"
        assert "authorization" not in req.headers            # no credential of any kind is sent
        if len(seen["posts"]) <= pending:
            return httpx.Response(202, json={"status": "pending"})
        q = parse_qs(urlparse(seen["url"]).query)
        assert hashlib.sha256(body["verifier"].encode()).hexdigest() == q["c"][0]      # the verifier is the secret behind the URL's challenge
        assert body["nonce"] == q["cli"][0]
        return httpx.Response(final[0], json=final[1])
    return seen, httpx.MockTransport(handler)


def opener(seen, ok=True):
    def open_url(url):
        seen["url"] = url
        return ok
    return open_url


def test_opens_the_browser_polls_then_saves_the_key(cfg_dir, capsys, monkeypatch):
    monkeypatch.setattr("socket.gethostname", lambda: "dev-laptop")
    seen, tr = cloud_that()
    sleeps = []
    assert run_cloud_browser_init(argparse.Namespace(cloud_url="https://app.test", token=None), transport=tr, open_url=opener(seen), sleep=sleeps.append) == 0
    u = urlparse(seen["url"]); q = parse_qs(u.query)
    assert f"{u.scheme}://{u.netloc}{u.path}" == "https://app.test/authorize" and q["m"] == ["dev-laptop"]
    assert len(q["cli"][0]) >= 32 and len(q["c"][0]) == 64
    assert len(seen["posts"]) == 3 and len(sleeps) == 2
    out = capsys.readouterr().out
    assert q["c"][0][:4].upper() + "-" + q["c"][0][4:8].upper() in out                  # the code to compare with the page
    assert KEY not in out and "Connected this machine to Panel Cloud workspace \"Acme\"" in out
    saved = cloud.load_saved_config()
    assert saved["api_key"] == KEY and saved["workspace_id"] == "ws_acme" and saved["cloud_url"] == "https://app.test"
    assert (cfg_dir / "cloud.json").stat().st_mode & 0o777 == 0o600


def test_prints_the_link_when_no_browser_can_be_opened(cfg_dir, capsys):
    seen, tr = cloud_that(pending=0)
    assert run_cloud_browser_init(argparse.Namespace(cloud_url="https://app.test", token=None), transport=tr, open_url=opener(seen, ok=False), sleep=lambda s: None) == 0
    assert "Open this link yourself" in capsys.readouterr().out and seen["url"].startswith("https://app.test/authorize?cli=")


def test_a_browser_that_raises_is_not_fatal(cfg_dir, capsys):
    seen, tr = cloud_that(pending=0)
    def boom(url):
        seen["url"] = url
        raise RuntimeError("no display")
    assert run_cloud_browser_init(argparse.Namespace(cloud_url="https://app.test", token=None), transport=tr, open_url=boom, sleep=lambda s: None) == 0


def test_expired_or_used_request_is_a_clean_error_and_saves_nothing(cfg_dir):
    seen, tr = cloud_that(pending=1, final=(404, {"error": "gone"}))
    with pytest.raises(cloud.CloudError, match="expired"):
        cloud.browser_authorize("https://app.test", "m", transport=tr, open_url=opener(seen), say=lambda *_: None, sleep=lambda s: None)
    assert not (cfg_dir / "cloud.json").exists()


def test_times_out_instead_of_waiting_forever():
    t = [0.0]
    seen, tr = cloud_that(pending=10**6)
    def sleep(s): t[0] += s
    with pytest.raises(cloud.CloudError, match="timed out"):
        cloud.browser_authorize("https://app.test", "m", transport=tr, open_url=opener(seen), say=lambda *_: None, sleep=sleep, clock=lambda: t[0], timeout=60, interval=2)
    assert 20 <= len(seen["posts"]) <= 40


def test_unreachable_cloud_gives_up_after_a_few_tries():
    def h(req):
        raise httpx.ConnectError("down")
    with pytest.raises(cloud.CloudError, match="could not reach"):
        cloud.browser_authorize("https://app.test", "m", transport=httpx.MockTransport(h), open_url=lambda u: True, say=lambda *_: None, sleep=lambda s: None)


def test_a_reply_without_a_key_is_refused():
    seen, tr = cloud_that(pending=0, final=(200, {"api_key": "not-a-key", "workspace": {}}))
    with pytest.raises(cloud.CloudError, match="unexpected reply"):
        cloud.browser_authorize("https://app.test", "m", transport=tr, open_url=opener(seen), say=lambda *_: None, sleep=lambda s: None)


def test_plain_http_to_a_non_local_host_is_refused_before_a_browser_opens(cfg_dir, capsys):
    assert main(["init", "--cloud", "--cloud-url", "http://app.usepanel.dev"]) == 2
    assert "panel:" in capsys.readouterr().err


def test_flag_combinations(cfg_dir, capsys):
    assert main(["init", "--cloud", "--token", "pit_" + "t" * 24]) == 2
    assert "not both" in capsys.readouterr().err
    assert main(["init", "--cloud", "--", "some-mcp-server"]) == 2
    assert "no upstream" in capsys.readouterr().err
    assert main(["init", "--cloud-url", "https://app.usepanel.dev", "--", "x"]) == 2         # still needs --cloud or --token
