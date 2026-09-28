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
    redacted, _ = RedactionService(hash_key=b"k").redact(text, mask="hash")
    tokens = [word for word in redacted.split() if word.startswith("email_")]
    assert len(tokens) == 2
    assert tokens[0] == tokens[1]


def test_redact_hash_uses_the_injected_key():
    # The HMAC key is injected at construction, not baked in at import.
    text = "mail a@b.com"
    redacted_a, _ = RedactionService(hash_key=b"key-1").redact(text, mask="hash")
    redacted_b, _ = RedactionService(hash_key=b"key-2").redact(text, mask="hash")
    assert redacted_a != redacted_b


def test_hash_without_a_key_is_refused(monkeypatch):
    # No built-in key: a public default would make tokens reversible.
    monkeypatch.delenv("MASKON_HASH_KEY", raising=False)
    with pytest.raises(ValueError, match="needs a key"):
        RedactionService().redact("mail a@b.com", mask="hash")


def test_empty_hash_key_counts_as_missing(monkeypatch):
    monkeypatch.setenv("MASKON_HASH_KEY", "")
    with pytest.raises(ValueError, match="needs a key"):
        RedactionService().redact("mail a@b.com", mask="hash")


def test_label_and_partial_need_no_key(monkeypatch):
    monkeypatch.delenv("MASKON_HASH_KEY", raising=False)
    assert RedactionService().redact("mail a@b.com")[0] == "mail [EMAIL]"
    assert RedactionService().redact("mail a@b.com", mask="partial")[0] != ""


def test_explicit_empty_hash_key_is_refused(monkeypatch):
    # Same rule as an empty MASKON_HASH_KEY: an empty HMAC key is public.
    monkeypatch.delenv("MASKON_HASH_KEY", raising=False)
    with pytest.raises(ValueError, match="needs a key"):
        RedactionService(hash_key=b"").redact("mail a@b.com", mask="hash")
