"""Tests for the orchestration service — runs all detectors, merges results."""

import pytest

from maskon.service.redaction import RedactionService

service = RedactionService()


def test_detects_multiple_types_in_one_text():
    text = "SIREN 443061841, IBAN FR7630006000011234567890189, mail jean@example.com"
    findings = service.detect(text)
    types = {f.type for f in findings}
    assert types == {"SIREN", "IBAN", "EMAIL"}


def test_findings_are_sorted_by_position():
    text = "mail a@b.com then SIREN 443061841"
    findings = service.detect(text)
    starts = [f.start for f in findings]
    assert starts == sorted(starts)


def test_output_has_no_overlaps():
    text = "call 06 12 34 56 78 or write a@b.com"
    findings = service.detect(text)
    for earlier, later in zip(findings, findings[1:], strict=False):
        assert earlier.end <= later.start


def test_redact_returns_masked_text_and_findings():
    text = "IBAN FR7630006000011234567890189 mail a@b.com"
    redacted, findings = service.redact(text, mask="label")
    assert redacted == "IBAN [IBAN] mail [EMAIL]"
    assert {f.type for f in findings} == {"IBAN", "EMAIL"}


def test_redact_rejects_unknown_mask():
    # The core validates its own input — no reliance on the API layer.
    with pytest.raises(ValueError, match="unknown mask"):
        service.redact("anything", mask="banana")


def test_redact_hash_is_consistent_for_same_value():
    # The same email masked twice yields the same token → correlate without
    # revealing.
    text = "from a@b.com to a@b.com"
    redacted, _ = service.redact(text, mask="hash")
    tokens = [word for word in redacted.split() if word.startswith("email_")]
    assert len(tokens) == 2
    assert tokens[0] == tokens[1]
