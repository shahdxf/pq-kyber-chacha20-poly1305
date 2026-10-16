import os
import stat
import tempfile
from pathlib import Path

from pq_kyber_chacha.cli import main


def test_cli_roundtrip_and_failures():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        assert main(["keygen", "--out", str(d), "--name", "alice"]) == 0
        key = d / "alice.key"
        assert stat.S_IMODE(os.stat(key).st_mode) == 0o600  # private key is owner-only
        assert main(["keygen", "--out", str(d), "--name", "alice"]) == 1  # refuses to overwrite

        (d / "msg.txt").write_bytes("مرحبا, secret".encode())
        assert main(["encrypt", "--pub", str(d / "alice.pub"), "--in", str(d / "msg.txt"),
                     "--out", str(d / "msg.enc"), "--aad", "demo"]) == 0
        assert b"secret" not in (d / "msg.enc").read_bytes()
        assert main(["decrypt", "--key", str(key), "--in", str(d / "msg.enc"),
                     "--out", str(d / "out.txt"), "--aad", "demo"]) == 0
        assert (d / "out.txt").read_bytes() == (d / "msg.txt").read_bytes()
        assert main(["decrypt", "--key", str(key), "--in", str(d / "msg.enc"),
                     "--out", str(d / "x.txt"), "--aad", "other"]) == 2  # wrong context
