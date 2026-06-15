"""Tests for streaming redaction — the overlap-buffer logic."""

import pytest

from maskon.streaming.stream import redact_stream


def test_clean_text_passes_through_unchanged():
    chunks = ["hello ", "world, ", "nothing to hide here"]
    assert "".join(redact_stream(chunks)) == "hello world, nothing to hide here"


def test_redacts_pii_contained_in_one_chunk():
    chunks = ["start ", "mail a@b.com here ", "end"]
    assert "".join(redact_stream(chunks)) == "start mail [EMAIL] here end"


def test_pii_split_across_two_chunks_is_still_redacted():
    # The IBAN is cut in half at the chunk boundary. Without the overlap
    # buffer, neither chunk would see a valid IBAN and it would leak.
    head = "x" * 80 + " IBAN FR76 3000 60"
    tail = "00 0112 3456 7890 189 done"
    output = "".join(redact_stream([head, tail], overlap=64))
    assert "[IBAN]" in output  # caught despite the split
    assert "FR76" not in output  # nothing leaked in clear


def test_output_preserves_all_non_pii_text():
    # Joining the stream must reproduce the input, minus the masked spans.
    head = "x" * 80 + " IBAN FR76 3000 60"
    tail = "00 0112 3456 7890 189 done"
    output = "".join(redact_stream([head, tail], overlap=64))
    assert output == "x" * 80 + " IBAN [IBAN] done"


def test_rejects_unknown_mask():
    with pytest.raises(ValueError, match="unknown mask"):
        list(redact_stream(["text"], mask="banana"))
