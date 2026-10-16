"""python examples/basic.py   (after `pip install -e .`)"""
from dataclasses import replace

from pq_kyber_chacha import CIPHER_NAME, DecryptionError, decrypt, encrypt, generate_keypair

public_key, private_key = generate_keypair()
print(f"cipher: {CIPHER_NAME} | public key {len(public_key)} B (share) | private key {len(private_key)} B (keep secret)\n")

env = encrypt(public_key, "مرحبا - hello, post-quantum world".encode(), aad=b"conversation-42")
wire = env.to_bytes()
print(f"envelope: {len(wire)} B  (KEM ciphertext {len(env.kem_ciphertext)} B)")
print("decrypted :", decrypt(private_key, wire, aad=b"conversation-42").decode())

tampered = replace(env, ciphertext=bytes([env.ciphertext[0] ^ 1]) + env.ciphertext[1:])
for label, args in (("modified ciphertext", (tampered, b"conversation-42")),
                    ("different context  ", (env, b"conversation-43"))):
    try:
        decrypt(private_key, *args)
    except DecryptionError:
        print(f"{label}: rejected")
