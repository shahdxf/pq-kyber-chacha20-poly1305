# Changelog

## 0.1.0
- ML-KEM-768 + HKDF-SHA256 + ChaCha20-Poly1305.
- Versioned wire format; header and KEM ciphertext authenticated.
- `pqkyber-chacha` command-line tool (keygen, encrypt, decrypt).
- Test suite covering tamper detection across the whole envelope.
