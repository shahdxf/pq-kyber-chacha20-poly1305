class PQKyberError(Exception):
    """Base class for all errors raised by this package."""


class DecryptionError(PQKyberError):
    """Wrong key, tampered data, mismatched associated data, or a malformed envelope.

    The message is intentionally generic: it never says *which* check failed.
    """


class FormatError(PQKyberError):
    """The byte string is not a valid envelope (bad magic, version, cipher id or length)."""
