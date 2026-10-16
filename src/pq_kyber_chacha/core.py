"""Post-quantum hybrid encryption: ML-KEM-768 (Kyber) + HKDF-SHA256 + ChaCha20-Poly1305.

    recipient public key --ML-KEM-768--> shared secret --HKDF-SHA256--> 256-bit key --ChaCha20-Poly1305--> ciphertext
                                      └─▶ KEM ciphertext (only the private-key owner can open it)

Educational reference implementation. It implements no primitive itself:
ML-KEM comes from `kyber-py` (pure Python, NOT constant-time), ChaCha20-Poly1305 and HKDF from `cryptography`.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

from .errors import DecryptionError, FormatError

MAGIC = b"PQH"
VERSION = 1
CIPHER_NAME = "chacha20-poly1305"
CIPHER_ID = 1  # identifies ChaCha20-Poly1305 in the envelope header
KEM_PUBLIC_KEY_BYTES = 1184
KEM_SECRET_KEY_BYTES = 2400
KEM_CIPHERTEXT_BYTES = 1088
NONCE_BYTES = 12
TAG_BYTES = 16

_HEADER = struct.Struct(">3sBB")  # magic, version, cipher id (5 bytes)
_HEADER_BYTES = _HEADER.pack(MAGIC, VERSION, CIPHER_ID)


@dataclass(frozen=True)
class Envelope:
    """Everything the recipient needs, except the private key."""

    kem_ciphertext: bytes
    nonce: bytes
    ciphertext: bytes  # message + 16-byte authentication tag

    # wire format: magic(3) | version(1) | cipher id(1) | kem_ct(1088) | nonce(12) | ciphertext + tag
    def to_bytes(self) -> bytes:
        return _HEADER_BYTES + self.kem_ciphertext + self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "Envelope":
        if len(data) < _HEADER.size + KEM_CIPHERTEXT_BYTES + NONCE_BYTES + TAG_BYTES:
            raise FormatError("envelope too short")
        magic, version, cipher_id = _HEADER.unpack_from(data)
        if magic != MAGIC:
            raise FormatError("not a pq-kyber envelope")
        if version != VERSION:
            raise FormatError(f"unsupported version {version}")
        if cipher_id != CIPHER_ID:
            raise FormatError("envelope uses a different cipher than this build (ChaCha20-Poly1305)")
        i = _HEADER.size
        kem_ct = bytes(data[i : i + KEM_CIPHERTEXT_BYTES])
        i += KEM_CIPHERTEXT_BYTES
        return cls(kem_ct, bytes(data[i : i + NONCE_BYTES]), bytes(data[i + NONCE_BYTES :]))


def _derive_key(shared_secret: bytes, kem_ciphertext: bytes) -> bytes:
    # The cipher name and the KEM ciphertext are part of the HKDF `info`: the key is specific to one
    # encapsulation and one cipher.
    info = b"pq-kyber-chacha20-poly1305/v1|" + CIPHER_NAME.encode() + b"|" + kem_ciphertext
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)


def _full_aad(kem_ciphertext: bytes, aad: bytes) -> bytes:
    # Authenticate the header and the KEM ciphertext together with the caller's context.
    return _HEADER_BYTES + kem_ciphertext + aad


def generate_keypair() -> tuple[bytes, bytes]:
    """Returns ``(public_key, private_key)``."""
    return ML_KEM_768.keygen()


def encrypt(public_key: bytes, plaintext: bytes, aad: bytes = b"") -> Envelope:
    """Encrypt ``plaintext`` for the owner of ``public_key``.

    ``aad`` (associated data) is authenticated but not encrypted. Use it to bind the message to its context
    (e.g. a conversation id); the recipient must supply the same ``aad`` to decrypt.
    """
    shared_secret, kem_ct = ML_KEM_768.encaps(public_key)
    nonce = os.urandom(NONCE_BYTES)
    ct = ChaCha20Poly1305(_derive_key(shared_secret, kem_ct)).encrypt(nonce, plaintext, _full_aad(kem_ct, aad))
    return Envelope(kem_ct, nonce, ct)


def decrypt(private_key: bytes, envelope: Envelope | bytes, aad: bytes = b"") -> bytes:
    """Decrypt an :class:`Envelope` (or its ``to_bytes()`` form). Raises :class:`DecryptionError` on any failure."""
    try:
        env = Envelope.from_bytes(envelope) if isinstance(envelope, (bytes, bytearray)) else envelope
        shared_secret = ML_KEM_768.decaps(private_key, env.kem_ciphertext)
        key = _derive_key(shared_secret, env.kem_ciphertext)
        return ChaCha20Poly1305(key).decrypt(env.nonce, env.ciphertext, _full_aad(env.kem_ciphertext, aad))
    except DecryptionError:
        raise
    except Exception as exc:  # bad tag, wrong key, wrong aad, malformed KEM data: all look the same
        raise DecryptionError("decryption failed") from exc
