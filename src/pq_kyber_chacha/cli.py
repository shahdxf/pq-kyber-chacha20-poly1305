"""Command line interface:  pqkyber-chacha keygen | encrypt | decrypt   (ChaCha20-Poly1305)"""
from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from . import CIPHER_NAME, DecryptionError, __version__, decrypt, encrypt, generate_keypair


def _write_private(path: Path, data: bytes) -> None:
    """Create the file readable only by the owner from the start (no window with wider permissions)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _cmd_keygen(a: argparse.Namespace) -> int:
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    pub_path, priv_path = out / f"{a.name}.pub", out / f"{a.name}.key"
    if pub_path.exists() or priv_path.exists():
        print("error: key files already exist; refusing to overwrite", file=sys.stderr)
        return 1
    pub, priv = generate_keypair()
    pub_path.write_bytes(base64.b64encode(pub))
    _write_private(priv_path, base64.b64encode(priv))
    print(f"public key : {pub_path}  (share it)")
    print(f"private key: {priv_path}  (keep it secret)")
    return 0


def _cmd_encrypt(a: argparse.Namespace) -> int:
    pub = base64.b64decode(Path(a.pub).read_bytes())
    env = encrypt(pub, Path(a.infile).read_bytes(), aad=a.aad.encode())
    Path(a.outfile).write_bytes(env.to_bytes())
    print(f"encrypted {a.infile} -> {a.outfile} ({CIPHER_NAME})")
    return 0


def _cmd_decrypt(a: argparse.Namespace) -> int:
    priv = base64.b64decode(Path(a.key).read_bytes())
    try:
        plain = decrypt(priv, Path(a.infile).read_bytes(), aad=a.aad.encode())
    except DecryptionError:
        print("error: decryption failed (wrong key, wrong --aad, or the file was modified)", file=sys.stderr)
        return 2
    Path(a.outfile).write_bytes(plain)
    print(f"decrypted {a.infile} -> {a.outfile}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pqkyber-chacha", description="Post-quantum hybrid file encryption, ChaCha20-Poly1305 (educational).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate an ML-KEM-768 key pair")
    k.add_argument("--out", default=".", help="directory for the key files")
    k.add_argument("--name", default="id", help="file name prefix (default: id)")
    k.set_defaults(func=_cmd_keygen)

    e = sub.add_parser("encrypt", help="encrypt a file for a public key")
    e.add_argument("--pub", required=True)
    e.add_argument("--in", dest="infile", required=True)
    e.add_argument("--out", dest="outfile", required=True)
    e.add_argument("--aad", default="", help="context string that must match when decrypting")
    e.set_defaults(func=_cmd_encrypt)

    d = sub.add_parser("decrypt", help="decrypt a file with a private key")
    d.add_argument("--key", required=True)
    d.add_argument("--in", dest="infile", required=True)
    d.add_argument("--out", dest="outfile", required=True)
    d.add_argument("--aad", default="")
    d.set_defaults(func=_cmd_decrypt)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
