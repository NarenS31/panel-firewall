"""The key fingerprint Panel Cloud shows and `usepanel fingerprint` prints must be the same string."""
import json
import re
import subprocess
import sys

from panel_firewall.firewall.receipts import fingerprint
from tests.fw_helpers import _KEY, signer

# Same vector as the cloud's test (test/receiptkey.test.ts): a public key made by the real engine and its fingerprint computed in Python.
VECTOR = ("Db4nKR7tukdy6MRs4J+Xem0XWnponp87xrucj/P8Dis=", "D3DB 6DD9 EEA5 0F31 0EF1 6631 D453 367D")


def test_known_vector():
    assert fingerprint(VECTOR[0]) == VECTOR[1]


def test_shape_and_sensitivity():
    fp = fingerprint(signer().pubkey)
    assert re.fullmatch(r"(?:[0-9A-F]{4} ){7}[0-9A-F]{4}", fp)
    other = signer().pubkey[:-3] + ("AAA" if not signer().pubkey.endswith("AAA") else "BBB")
    assert fingerprint(other) != fp


def test_cli_prints_the_fingerprint_of_the_key(tmp_path):
    r = subprocess.run([sys.executable, "-m", "panel_firewall.firewall", "fingerprint", "--key", str(_KEY)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert fingerprint(signer().pubkey) in r.stdout and "confirm the key only if" in r.stdout
    assert "BEGIN" not in r.stdout and signer().seed not in r.stdout          # never prints the private key
