"""`usepanel init --token`: one-command Panel Cloud setup, the saved config, and that proxy/doctor fall back to it."""
import argparse
import json
import os
import socket
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from panel_firewall.firewall import cloud
from panel_firewall.firewall.cli import main
from panel_firewall.firewall.doctor import OK, render, run_checks
from panel_firewall.firewall.types import FirewallError
from tests.test_fw_cloud import FakeCloud

KEY = "pcl_" + "s" * 30
TOKEN = "pit_" + "t" * 24


@pytest.fixture
def cfg_dir(tmp_path, monkeypatch):
    d = tmp_path / "cfg" / "usepanel"
    monkeypatch.setenv("PANEL_CONFIG_DIR", str(d))
    monkeypatch.delenv("PANEL_API_KEY", raising=False)
    return d


class InitServer:
    """A real HTTP server on 127.0.0.1 playing the Panel Cloud /v1/proxy/init endpoint."""
    def __init__(self, status=200, body=None):
        self.status, self.requests = status, []
        self.body = body if body is not None else {"api_key": KEY, "workspace": {"id": "ws_acme", "name": "Acme"}, "key_id": "key_1"}
        srv = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                srv.requests.append({"path": self.path, "headers": dict(self.headers), "body": json.loads(raw or b"{}")})
                data = json.dumps(srv.body).encode()
                self.send_response(srv.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    made = []

    def make(**kw):
        s = InitServer(**kw)
        made.append(s)
        return s
    yield make
    for s in made:
        s.close()


def write_saved(cfg_dir, url="https://cloud.test", key=KEY):
    cfg_dir.mkdir(parents=True, exist_ok=True)
    p = cfg_dir / "cloud.json"
    p.write_text(json.dumps({"cloud_url": url, "api_key": key, "workspace_id": "ws_acme", "workspace_name": "Acme", "key_id": "key_1"}))
    os.chmod(p, 0o600)
    return p


# ------------------------------------------------------------------------------------------------ init --token
def test_success_writes_a_private_config_and_never_prints_the_key(cfg_dir, server, capsys):
    s = server()
    assert main(["init", "--token", TOKEN, "--cloud-url", s.url + "//"]) == 0
    out = capsys.readouterr()
    p = cfg_dir / "cloud.json"
    assert json.loads(p.read_text()) == {"cloud_url": s.url, "api_key": KEY, "workspace_id": "ws_acme", "workspace_name": "Acme", "key_id": "key_1"}
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(cfg_dir.stat().st_mode) == 0o700
    assert [x.name for x in cfg_dir.iterdir()] == ["cloud.json"]                # atomic write leaves no temp file behind
    assert KEY not in out.out + out.err and KEY[4:] not in out.out + out.err and TOKEN not in out.out
    assert "Acme" in out.out and str(p) in out.out
    assert "usepanel proxy -- <your MCP server command>" in out.out and "usepanel doctor" in out.out
    [req] = s.requests
    assert req["path"] == "/v1/proxy/init"
    assert req["body"] == {"token": TOKEN, "machine": socket.gethostname()}
    assert not any(k.lower() == "authorization" for k in req["headers"])


def test_404_gives_the_friendly_error_and_writes_nothing(cfg_dir, server, capsys):
    s = server(status=404, body={"error": "this setup command is invalid, used or expired; make a new one in the dashboard"})
    assert main(["init", "--token", TOKEN, "--cloud-url", s.url]) == 2
    err = capsys.readouterr().err
    assert "invalid, already used or expired" in err and "dashboard" in err and TOKEN not in err
    assert not (cfg_dir / "cloud.json").exists()


def test_429_says_how_long_to_wait(cfg_dir, server, capsys):
    s = server(status=429, body={"error": "slow down", "retry_after": 42})
    assert main(["init", "--token", TOKEN, "--cloud-url", s.url]) == 2
    assert "wait 42 seconds" in capsys.readouterr().err
    assert not (cfg_dir / "cloud.json").exists()


def test_network_failure_is_a_clear_error(cfg_dir, capsys):
    with socket.socket() as so:                   # a port nothing listens on
        so.bind(("127.0.0.1", 0)); port = so.getsockname()[1]
    assert main(["init", "--token", TOKEN, "--cloud-url", f"http://127.0.0.1:{port}"]) == 2
    err = capsys.readouterr().err
    assert "could not reach Panel Cloud" in err and "--cloud-url" in err
    assert not (cfg_dir / "cloud.json").exists()


def test_unexpected_reply_writes_nothing(cfg_dir, server, capsys):
    s = server(body={"ok": True})
    assert main(["init", "--token", TOKEN, "--cloud-url", s.url]) == 2
    assert "unexpected reply" in capsys.readouterr().err
    assert not (cfg_dir / "cloud.json").exists()


@pytest.mark.parametrize("url", ["http://app.usepanel.dev", "http://10.0.0.5:8787", "ftp://x.test", "not a url"])
def test_plain_http_to_a_non_local_host_is_refused_before_any_request(cfg_dir, capsys, url):
    assert main(["init", "--token", TOKEN, "--cloud-url", url]) == 2
    assert "panel:" in capsys.readouterr().err
    assert not (cfg_dir / "cloud.json").exists()


def test_default_cloud_url_and_localhost_http_allowed():
    assert cloud.normalize_cloud_url("http://localhost:8787/") == "http://localhost:8787"
    assert cloud.normalize_cloud_url("https://app.usepanel.dev///") == "https://app.usepanel.dev"
    seen = []

    def h(req):
        seen.append(str(req.url))
        return httpx.Response(200, json={"api_key": KEY, "workspace": {"id": "ws_1", "name": "W"}, "key_id": "key_9"})
    from panel_firewall.firewall.init import run_cloud_init
    assert run_cloud_init(argparse.Namespace(token=TOKEN, cloud_url=None), transport=httpx.MockTransport(h)) == 0
    assert seen == ["https://app.usepanel.dev/v1/proxy/init"]
    assert cloud.load_saved_config()["cloud_url"] == "https://app.usepanel.dev"


def test_token_must_look_like_a_setup_token_and_takes_no_upstream(cfg_dir, capsys):
    assert main(["init", "--token", KEY]) == 2
    err = capsys.readouterr().err
    assert "pit_" in err and "API key" in err and KEY not in err
    assert main(["init", "--token", TOKEN, "--", "some-mcp-server"]) == 2
    assert "no upstream" in capsys.readouterr().err
    assert main(["init", "--cloud-url", "https://app.usepanel.dev", "--", "x"]) == 2
    assert main(["init"]) == 2                          # the local-policy form still needs an upstream, as before
    assert "-- <upstream command>" in capsys.readouterr().err


def test_rerun_replaces_the_previous_setup(cfg_dir, server, capsys):
    write_saved(cfg_dir, key="pcl_old_key_0000000000")
    s = server(body={"api_key": KEY, "workspace": {"id": "ws_other", "name": "Other"}, "key_id": "key_2"})
    assert main(["init", "--token", TOKEN, "--cloud-url", s.url]) == 0
    assert "replaced the previous setup for workspace Acme" in capsys.readouterr().out
    assert cloud.load_saved_config()["api_key"] == KEY


def test_xdg_config_home_is_honoured(tmp_path, monkeypatch):
    monkeypatch.delenv("PANEL_CONFIG_DIR", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert cloud.config_path() == tmp_path / "xdg" / "usepanel" / "cloud.json"
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert cloud.config_path() == tmp_path / ".config" / "usepanel" / "cloud.json"


# ------------------------------------------------------------------------------------------------ precedence
def ns(**kw):
    base = dict(cloud_url=None, api_key=None, api_key_file=None, policy=None)
    base.update(kw)
    return argparse.Namespace(**base)


def test_explicit_key_sources_override_the_saved_config(cfg_dir, tmp_path, monkeypatch):
    write_saved(cfg_dir)
    assert cloud.resolve_api_key(ns(cloud_url="https://cloud.test"))[0] == KEY
    assert cloud.resolve_api_key(ns(cloud_url="https://cloud.test"))[1].startswith("saved config")
    assert cloud.read_api_key(ns(cloud_url="https://cloud.test", api_key="pcl_flag")) == "pcl_flag"
    kf = tmp_path / "k.txt"; kf.write_text("pcl_file\n")
    assert cloud.read_api_key(ns(cloud_url="https://cloud.test", api_key_file=str(kf))) == "pcl_file"
    monkeypatch.setenv("PANEL_API_KEY", "pcl_env")
    assert cloud.resolve_api_key(ns(cloud_url="https://cloud.test")) == ("pcl_env", "PANEL_API_KEY")
    assert cloud.read_api_key(ns(cloud_url="https://cloud.test", api_key="pcl_flag")) == "pcl_flag"
    monkeypatch.delenv("PANEL_API_KEY")
    empty = tmp_path / "empty.txt"; empty.write_text("")
    with pytest.raises(FirewallError, match="is empty"):             # an explicit empty file is not silently replaced
        cloud.read_api_key(ns(cloud_url="https://cloud.test", api_key_file=str(empty)))


def test_saved_key_is_never_sent_to_a_different_cloud(cfg_dir):
    write_saved(cfg_dir, url="https://cloud.test")
    with pytest.raises(FirewallError, match="saved config .* is for https://cloud.test"):
        cloud.read_api_key(ns(cloud_url="https://evil.test"))
    assert cloud.read_api_key(ns(cloud_url="https://cloud.test/")) == KEY


def test_damaged_saved_config_is_a_clear_error(cfg_dir):
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "cloud.json").write_text("{not json")
    with pytest.raises(FirewallError, match="usepanel init --token"):
        cloud.load_saved_config()


# ------------------------------------------------------------------------------------------------ proxy and doctor use it
@pytest.fixture
def fake_cloud(monkeypatch):
    fc = FakeCloud()
    seen = []

    def handler(req):
        seen.append(req.headers.get("authorization"))
        return fc.handler(req)

    class Client(cloud.CloudClient):
        def __init__(self, url, api_key, timeout=10.0, transport=None):
            seen.append(url)
            super().__init__(url, api_key, timeout, transport=httpx.MockTransport(handler))
    monkeypatch.setattr(cloud, "CloudClient", Client)
    return seen


def test_proxy_with_no_flags_uses_the_saved_cloud_and_key(cfg_dir, tmp_path, fake_cloud):
    from panel_firewall.firewall.gateway import _prepare_cloud
    write_saved(cfg_dir)
    a = ns(cloud_state_dir=str(tmp_path / "st"), cloud_pubkey=None, ledger=None)
    _prepare_cloud(a)
    assert a.cloud_url == "https://cloud.test" and Path(a.policy).is_file()
    assert fake_cloud[0] == "https://cloud.test" and f"Bearer {KEY}" in fake_cloud


def test_proxy_with_an_explicit_key_or_local_policy_ignores_the_saved_setup(cfg_dir, tmp_path, fake_cloud):
    from panel_firewall.firewall.gateway import _prepare_cloud
    write_saved(cfg_dir)
    a = ns(api_key="pcl_override_key_000000", cloud_state_dir=str(tmp_path / "st"), cloud_pubkey=None, ledger=None)
    _prepare_cloud(a)
    assert "Bearer pcl_override_key_000000" in fake_cloud and f"Bearer {KEY}" not in fake_cloud
    local = ns(policy=str(tmp_path / "p.yaml"))
    _prepare_cloud(local)
    assert local.cloud_url is None


def test_proxy_with_nothing_configured_points_at_init(cfg_dir):
    from panel_firewall.firewall.gateway import _prepare_cloud
    with pytest.raises(FirewallError, match="usepanel init --token"):
        _prepare_cloud(ns())


def ping(req):
    assert req.url.path == "/v1/proxy/ping"
    return httpx.Response(200 if req.headers.get("authorization") == f"Bearer {KEY}" else 401,
                          json={"workspace_id": "ws_acme", "mode": "shadow", "policy_version": 1})


def doctor_args(**kw):
    base = dict(cloud_url=None, api_key=None, api_key_file=None, key=None, pin_file=None, policy=None, upstream=[], cloud_state_dir=None)
    base.update(kw)
    return argparse.Namespace(**base)


def test_doctor_uses_the_saved_setup_and_says_where_the_key_came_from(cfg_dir, tmp_path):
    p = write_saved(cfg_dir)
    cs = run_checks(doctor_args(cloud_state_dir=str(tmp_path / "st")), transport=httpx.MockTransport(ping))
    by = {c.name: c for c in cs}
    assert by["Saved Panel Cloud setup"].status == OK and "Acme" in by["Saved Panel Cloud setup"].detail
    assert by["Panel Cloud API key"].status == OK and f"from saved config {p}" in by["Panel Cloud API key"].detail
    assert by["Panel Cloud reachable"].status == OK
    text = render(cs)
    assert KEY not in text and KEY[8:] not in text


def test_doctor_reports_flag_and_env_overrides(cfg_dir, tmp_path, monkeypatch):
    write_saved(cfg_dir)
    cs = run_checks(doctor_args(api_key="pcl_" + "f" * 30, cloud_state_dir=str(tmp_path / "st")), transport=httpx.MockTransport(ping))
    by = {c.name: c for c in cs}
    assert "from --api-key" in by["Panel Cloud API key"].detail
    assert by["Panel Cloud API key accepted"].status != OK                    # the override really is what was sent
    monkeypatch.setenv("PANEL_API_KEY", KEY)
    by = {c.name: c for c in run_checks(doctor_args(cloud_state_dir=str(tmp_path / "st")), transport=httpx.MockTransport(ping))}
    assert "from PANEL_API_KEY" in by["Panel Cloud API key"].detail


def test_doctor_warns_on_a_readable_config_and_skips_it_with_a_local_policy(cfg_dir, tmp_path):
    p = write_saved(cfg_dir)
    os.chmod(p, 0o644)
    by = {c.name: c for c in run_checks(doctor_args(cloud_state_dir=str(tmp_path / "st")), transport=httpx.MockTransport(ping))}
    assert by["Saved config permissions"].status == "warn" and "chmod 600" in by["Saved config permissions"].fix
    names = [c.name for c in run_checks(doctor_args(policy=str(tmp_path / "nope.yaml")))]
    assert "Local policy file" in names and "Saved Panel Cloud setup" not in names
