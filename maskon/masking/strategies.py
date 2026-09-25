"""Masking strategies.

A strategy decides what a single piece of PII becomes. It receives the original
matched text and its type, and returns the replacement string. It knows nothing
about positions or the rest of the text — that is the applier's job.
"""

import hashlib
import hmac
import os

from maskon.masking.apply import Strategy


def label(original: str, pii_type: str) -> str:
    """Irreversible, readable: replace the value by its type, e.g. "[IBAN]"."""
    return f"[{pii_type}]"


def partial(original: str, pii_type: str) -> str:
    """Keep the edges, mask the middle: "FR76****189". Handy for support."""
    keep_start, keep_end = 4, 3
    if len(original) <= keep_start + keep_end:
        return "*" * len(original)
    return original[:keep_start] + "****" + original[-keep_end:]


def hash_strategy(key: bytes) -> Strategy:
    """Deterministic pseudonymisation: the same value always maps to the same
    token (e.g. "iban_3f2a9c1b"), so masked data can still be correlated without
    revealing it. Keyed with HMAC-SHA256, so the mapping can't be reversed by
    brute-forcing the (short) input space without the key.
    """

    def _hash(original: str, pii_type: str) -> str:
        digest = hmac.new(key, original.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{pii_type.lower()}_{digest[:8]}"

    return _hash


class MissingHashKey(ValueError):
    """`hash` was requested but no key is configured."""


def default_hash_key() -> bytes | None:
    # Read at service construction (not at import). Deliberately no built-in
    # fallback: a public default key would make every token reversible by
    # dictionary over short inputs (a phone number, a NIR). Unset → None.
    key = os.environ.get("MASKON_HASH_KEY", "")
    return key.encode("utf-8") or None


def build_strategies(hash_key: bytes | None) -> dict[str, Strategy]:
    """The strategies available to a service, given the (injected) hash key.
    Without a key (None or empty), `hash` is not available — `label` and
    `partial` still are."""
    strategies: dict[str, Strategy] = {"label": label, "partial": partial}
    if hash_key:
        strategies["hash"] = hash_strategy(hash_key)
    return strategies
