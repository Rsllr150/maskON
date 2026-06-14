"""Tests for the SIREN detector — written before the implementation (TDD)."""

from maskon.detectors.siren import SirenDetector

detector = SirenDetector()


def test_finds_a_valid_siren():
    text = "SIREN 443061841 here"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "SIREN"
    assert text[f.start : f.end] == "443061841"
    assert f.confidence == 1.0


def test_tolerates_spaces():
    text = "Number 443 061 841 valid"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "443 061 841"


def test_ignores_bad_checksum():
    # Right shape (9 digits) but wrong Luhn key → not a SIREN.
    text = "Invoice 443061842 this month"
    assert detector.detect(text) == []


def test_text_without_siren():
    assert detector.detect("Hello, nothing here.") == []
