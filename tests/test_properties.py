"""Property-based tests (Hypothesis).

Instead of hand-picked examples, generate thousands of inputs and assert
invariants that must hold for *all* of them. This is where subtle bugs hide —
especially around chunk boundaries in the streaming redactor.
"""

import hypothesis.strategies as st
from hypothesis import given, settings

from maskon.service.redaction import RedactionService
from maskon.streaming.stream import redact_stream

service = RedactionService()

# A pool of genuinely valid PII (checksums pass) to embed in generated text.
VALID_PII = [
    "FR7630006000011234567890189",  # IBAN
    "FR76 3000 6000 0112 3456 7890 189",  # IBAN, spaced
    "DE89370400440532013000",  # IBAN
    "jean.dupont@example.com",  # email
    "a@b.com",  # email
    "06 12 34 56 78",  # phone
    "0142685300",  # phone
    "443061841",  # SIREN
    "255083352108827",  # NIR
    "4111111111111111",  # bank card
]

# Filler made only of letters/spaces: it can never create or merge into a PII
# (no digits, no "@"), so embedded PII stay cleanly detectable.
_filler = st.text(alphabet="abcdefghijklmnop ", max_size=25)
_segment = st.one_of(_filler, st.sampled_from(VALID_PII))
# Space-joined so each PII is a standalone token.
_pii_text = st.lists(_segment, max_size=8).map(" ".join)


@given(text=_pii_text, chunk_size=st.integers(min_value=1, max_value=12))
@settings(max_examples=300)
def test_streaming_equals_batch_for_any_chunking(text: str, chunk_size: int):
    # The core invariant: however the text is sliced into chunks, streaming
    # must produce exactly what a single-shot redaction produces. This is the
    # proof that the sliding overlap buffer handles boundary-straddling PII.
    chunks = [text[i : i + chunk_size] for i in range(0, len(text), chunk_size)]
    streamed = "".join(redact_stream(chunks, mask="label", overlap=64))
    batch, _ = service.redact(text, mask="label")
    assert streamed == batch


@given(text=st.text(max_size=200))
@settings(max_examples=300)
def test_detect_returns_wellformed_findings(text: str):
    # On *any* input, detection must not crash and must return in-bounds,
    # sorted, non-overlapping spans.
    findings = service.detect(text)
    for f in findings:
        assert 0 <= f.start < f.end <= len(text)
    for earlier, later in zip(findings, findings[1:], strict=False):
        assert earlier.end <= later.start


@given(text=_pii_text)
@settings(max_examples=300)
def test_label_masking_never_leaks_a_detected_value(text: str):
    # Every detected PII value must be gone from the redacted output.
    findings = service.detect(text)
    redacted, _ = service.redact(text, mask="label")
    for f in findings:
        assert text[f.start : f.end] not in redacted
