"""maskON — detect and mask French structured identifiers, each proven by its checksum.

    >>> import maskon
    >>> maskon.redact("IBAN FR7630006000011234567890189")
    'IBAN [IBAN]'

The public API is exactly what `__all__` lists; it follows semver. Every other
module and name (`maskon.service`, `maskon.detectors`, ...) is internal and may
change in any release. The core has no dependency; the HTTP service lives in
`maskon.api` and needs the extra: `pip install "maskon[api]"`.
"""

from collections.abc import Iterable, Iterator
from typing import Literal

from maskon.models import Finding
from maskon.service.redaction import RedactionService
from maskon.streaming.stream import DEFAULT_OVERLAP
from maskon.streaming.stream import redact_stream as _redact_stream

# The single source of the version: pyproject.toml reads it (dynamic).
__version__ = "0.1.0"

__all__ = ["Finding", "__version__", "detect", "redact", "redact_stream"]

Mask = Literal["label", "partial", "hash"]


def detect(text: str) -> list[Finding]:
    """Locate PII in `text`, without masking. Findings never overlap."""
    return RedactionService().detect(text)


def redact(
    text: str,
    mask: Mask = "label",
    *,
    hash_key: bytes | None = None,
    hash_key_version: str | None = None,
) -> str:
    """Return `text` with every PII masked. Never raises on any text.

    `mask`: "label" → `[IBAN]`, "partial" → what the type can safely show
    (`FR****0189`, `j****@example.com`, `****` for a SIREN), "hash" → a keyed,
    deterministic token (`iban_v1_3f2a9c1b0d4e7a65`). `hash_key` keys the hash
    and must be at least 16 bytes; when omitted, the MASKON_HASH_KEY
    environment variable is read on each call. There is no default key: `hash`
    without one raises ValueError. `hash_key_version` (default
    MASKON_HASH_KEY_VERSION, else "v1") goes into the token, for key rotation.
    """
    service = RedactionService(hash_key=hash_key, hash_key_version=hash_key_version)
    redacted, _ = service.redact(text, mask=mask)
    return redacted


def redact_stream(
    chunks: Iterable[str],
    mask: Mask = "label",
    *,
    hash_key: bytes | None = None,
    hash_key_version: str | None = None,
    overlap: int = DEFAULT_OVERLAP,
) -> Iterator[str]:
    """Redact an iterable of text chunks with bounded memory, yielding output.

    A PII split across two chunks is still caught, provided `overlap` exceeds
    the longest PII (the default does).
    """
    service = RedactionService(hash_key=hash_key, hash_key_version=hash_key_version)
    service.strategy_for(mask)  # fail now, like redact(), not at first next()
    return _redact_stream(chunks, mask=mask, overlap=overlap, service=service)
