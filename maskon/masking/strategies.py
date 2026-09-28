"""Masking strategies.

A strategy decides what a single piece of PII becomes. It receives the original
matched text and its type, and returns the replacement string. It knows nothing
about positions or the rest of the text — that is the applier's job.
"""

import hashlib
import hmac
import os
import re

from maskon.masking.apply import Strategy


def label(original: str, pii_type: str) -> str:
    """Irreversible, readable: replace the value by its type, e.g. "[IBAN]"."""
    return f"[{pii_type}]"


_HIDDEN = "****"  # fixed width: the mask never reveals the value's length


def _significant(original: str) -> str:
    # The value without its separators (spaces, dashes, dots).
    return "".join(c for c in original if c.isalnum())


def partial(original: str, pii_type: str) -> str:
    """Keep only what a type can safely show, for support. Per type (AUDIT §5):
    CB the first 6 + last 4 digits (the PCI-DSS maximum, only from 16 digits
    up, else the last 4); EMAIL the first letter + the domain; TEL the last 2
    digits; IBAN the country + the last 4. Every other type is fully hidden:
    SIREN, NIR and the rest are short enough that any edge makes them guessable.
    """
    value = _significant(original)
    if pii_type == "CB":
        if len(value) >= 16:
            return value[:6] + _HIDDEN + value[-4:]
        return _HIDDEN + value[-4:]
    if pii_type == "EMAIL":
        local, _, domain = original.rpartition("@")
        return local[:1] + _HIDDEN + "@" + domain
    if pii_type == "TEL":
        return _HIDDEN + value[-2:]
    if pii_type == "IBAN":
        return value[:2].upper() + _HIDDEN + value[-4:]
    return _HIDDEN


def hash_strategy(key: bytes, version: str = "v1") -> Strategy:
    """Deterministic pseudonymisation: the same value always maps to the same
    token (e.g. "iban_v1_3f2a9c1b0d4e7a65"), so masked data can still be
    correlated without revealing it. Keyed with HMAC-SHA256, so the mapping
    can't be reversed by brute-forcing the (short) input space without the key.
    64 bits keep collisions negligible (32 bits collided from ~77k values), and
    the key version in the token lets a key be rotated.
    """

    def _hash(original: str, pii_type: str) -> str:
        digest = hmac.new(key, original.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{pii_type.lower()}_{version}_{digest[:16]}"

    return _hash


class MissingHashKey(ValueError):
    """`hash` was requested but no key is configured."""


class WeakHashKey(ValueError):
    """The hash key is shorter than MIN_HASH_KEY_BYTES."""


MIN_HASH_KEY_BYTES = 16
DEFAULT_HASH_KEY_VERSION = "v1"
_VERSION = re.compile(r"[A-Za-z0-9]{1,16}")


def default_hash_key() -> bytes | None:
    # Read at service construction (not at import). Deliberately no built-in
    # fallback: a public default key would make every token reversible by
    # dictionary over short inputs (a phone number, a NIR). Unset → None.
    key = os.environ.get("MASKON_HASH_KEY", "")
    return key.encode("utf-8") or None


def default_hash_key_version() -> str:
    return os.environ.get("MASKON_HASH_KEY_VERSION", "") or DEFAULT_HASH_KEY_VERSION


def build_strategies(
    hash_key: bytes | None, hash_key_version: str = DEFAULT_HASH_KEY_VERSION
) -> dict[str, Strategy]:
    """The strategies available to a service, given the (injected) hash key.
    Without a key (None or empty), `hash` is not available — `label` and
    `partial` still are. A key that is set but too short, or a malformed
    version, is refused right here: a weak key must not wait for the first
    `hash` call to be noticed."""
    if hash_key and len(hash_key) < MIN_HASH_KEY_BYTES:
        raise WeakHashKey(
            f"hash key must be at least {MIN_HASH_KEY_BYTES} bytes, got {len(hash_key)}"
        )
    if not _VERSION.fullmatch(hash_key_version):
        raise ValueError(
            f"hash key version must be 1-16 letters or digits, got {hash_key_version!r}"
        )
    strategies: dict[str, Strategy] = {"label": label, "partial": partial}
    if hash_key:
        strategies["hash"] = hash_strategy(hash_key, hash_key_version)
    return strategies
