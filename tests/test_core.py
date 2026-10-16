import pytest

from pq_kyber_chacha import DecryptionError, Envelope, FormatError, decrypt, encrypt, generate_keypair


@pytest.fixture(scope="module")
def keys():
    return generate_keypair(), generate_keypair()


def test_roundtrip(keys):
    (pub, priv), _ = keys
    msg = "hello مرحبا 🔐".encode()
    assert decrypt(priv, encrypt(pub, msg, b"ctx"), b"ctx") == msg


def test_empty_and_large_messages(keys):
    (pub, priv), _ = keys
    for msg in (b"", b"\x00" * 1_000_000):
        assert decrypt(priv, encrypt(pub, msg)) == msg


def test_ciphertext_does_not_contain_plaintext(keys):
    (pub, _), _ = keys
    assert b"top secret" not in encrypt(pub, b"top secret message").to_bytes()


def test_same_message_encrypts_differently(keys):
    (pub, _), _ = keys
    a, b = encrypt(pub, b"same"), encrypt(pub, b"same")
    assert a.ciphertext != b.ciphertext and a.nonce != b.nonce and a.kem_ciphertext != b.kem_ciphertext


def test_wrong_private_key_fails(keys):
    (pub, _), (_, other_priv) = keys
    with pytest.raises(DecryptionError):
        decrypt(other_priv, encrypt(pub, b"x"))


def test_every_region_is_authenticated(keys):
    """Flipping one bit in the header, KEM ciphertext, nonce, body or tag must be rejected."""
    (pub, priv), _ = keys
    raw = bytearray(encrypt(pub, b"payload", b"ctx").to_bytes())
    for pos in (0, 3, 4, 5, 5 + 100, 5 + 1088, 5 + 1088 + 12, len(raw) - 17, len(raw) - 1):
        bad = bytearray(raw)
        bad[pos] ^= 1
        with pytest.raises((DecryptionError, FormatError)):
            decrypt(priv, bytes(bad), b"ctx")


def test_different_associated_data_fails(keys):
    (pub, priv), _ = keys
    env = encrypt(pub, b"payload", b"context-A")
    with pytest.raises(DecryptionError):
        decrypt(priv, env, b"context-B")


def test_wire_format_roundtrip(keys):
    (pub, priv), _ = keys
    env = encrypt(pub, b"serialize me", b"a")
    again = Envelope.from_bytes(env.to_bytes())
    assert again == env and decrypt(priv, again, b"a") == b"serialize me"


def test_wire_format_rejects_garbage(keys):
    (pub, priv), _ = keys
    good = encrypt(pub, b"x").to_bytes()
    other_cipher = good[:4] + bytes([3 - good[4]]) + good[5:]  # a different cipher id
    for bad in (b"", b"PQH", good[:50], b"XXX" + good[3:], good[:3] + b"\x09" + good[4:], other_cipher):
        with pytest.raises(FormatError):
            Envelope.from_bytes(bad)
        with pytest.raises(DecryptionError):
            decrypt(priv, bad)


def test_error_message_is_generic(keys):
    """The error never says which check failed (no oracle)."""
    (pub, priv), _ = keys
    env = encrypt(pub, b"x", b"a")
    messages = set()
    for call in (lambda: decrypt(priv, env, b"b"), lambda: decrypt(priv, Envelope(env.kem_ciphertext, env.nonce, b"\0" * 20))):
        with pytest.raises(DecryptionError) as exc:
            call()
        messages.add(str(exc.value))
    assert messages == {"decryption failed"}
