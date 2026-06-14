"""Tests for the IBAN detector — written before the implementation (TDD)."""

from maskon.detectors.iban import IbanDetector

detector = IbanDetector()


def test_finds_a_spaced_iban():
    text = "Pay to IBAN FR76 3000 6000 0112 3456 7890 189 please"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "IBAN"
    assert text[f.start : f.end] == "FR76 3000 6000 0112 3456 7890 189"
    assert f.confidence == 1.0


def test_finds_a_compact_iban():
    text = "account DE89370400440532013000 end"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "DE89370400440532013000"


def test_finds_two_ibans():
    text = "GB82 WEST 1234 5698 7654 32 and FR7630006000011234567890189."
    findings = detector.detect(text)
    assert len(findings) == 2


def test_ignores_bad_checksum():
    # Right IBAN shape but the mod-97 check fails → not an IBAN.
    text = "wrong FR7630006000011234567890188 here"
    assert detector.detect(text) == []


def test_text_without_iban():
    assert detector.detect("Nothing relevant, just FR and words") == []
