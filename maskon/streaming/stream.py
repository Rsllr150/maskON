"""Stream redaction with a sliding overlap buffer — constant memory.

A PII can straddle two chunks (an IBAN cut in half at a chunk boundary). To
catch it without holding the whole input in memory, we keep a trailing window
of `overlap` characters between chunks: a split PII reappears whole there.

`overlap` MUST exceed the longest possible PII (IBANs reach ~40 characters with
spaces), otherwise a long PII could itself be cut and slip through.
"""

from collections.abc import Iterable, Iterator

from maskon.masking.apply import Strategy, apply_mask
from maskon.models import Finding
from maskon.service.redaction import RedactionService

DEFAULT_OVERLAP = 64


def _safe_cut(buffer: str, overlap: int, findings: list[Finding]) -> int:
    # We may emit everything except the last `overlap` characters, where a PII
    # could still be growing into the next chunk.
    cut = len(buffer) - overlap
    # Never cut through a finding that crosses the boundary: defer it whole.
    for f in findings:
        if f.start < cut < f.end:
            cut = min(cut, f.start)
    return cut


class StreamRedactor:
    """Feed text chunks in, get redacted text out, with bounded memory."""

    def __init__(
        self,
        mask: str = "label",
        overlap: int = DEFAULT_OVERLAP,
        service: RedactionService | None = None,
    ) -> None:
        self._service = service or RedactionService()
        # The service owns strategy resolution (and the hash key); this also
        # validates the mask name.
        self._strategy: Strategy = self._service.strategy_for(mask)
        self._overlap = overlap
        self._buffer = ""

    def feed(self, chunk: str) -> str:
        """Add a chunk; return the redacted text that is now safe to emit."""
        self._buffer += chunk
        if len(self._buffer) <= self._overlap:
            return ""  # not enough yet — a PII could span what we have

        findings = self._service.detect(self._buffer)
        cut = _safe_cut(self._buffer, self._overlap, findings)
        if cut <= 0:
            return ""

        safe = [f for f in findings if f.end <= cut]
        emitted = apply_mask(self._buffer[:cut], safe, self._strategy)
        self._buffer = self._buffer[cut:]
        return emitted

    def flush(self) -> str:
        """No more input is coming — redact and return whatever is left."""
        if not self._buffer:
            return ""
        findings = self._service.detect(self._buffer)
        out = apply_mask(self._buffer, findings, self._strategy)
        self._buffer = ""
        return out


def redact_stream(
    chunks: Iterable[str],
    mask: str = "label",
    overlap: int = DEFAULT_OVERLAP,
    service: RedactionService | None = None,
) -> Iterator[str]:
    redactor = StreamRedactor(mask=mask, overlap=overlap, service=service)
    for chunk in chunks:
        emitted = redactor.feed(chunk)
        if emitted:
            yield emitted
    tail = redactor.flush()
    if tail:
        yield tail
