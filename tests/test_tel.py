"""Tests for the TEL (French phone) detector — written before the impl (TDD)."""

from maskon.detectors.tel import TelDetector

detector = TelDetector()


def test_finds_spaced_mobile():
    text = "call me at 06 12 34 56 78 please"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "TEL"
    assert text[f.start : f.end] == "06 12 34 56 78"
    assert f.confidence < 1.0


def test_finds_various_formats():
    assert detector.detect("compact 0612345678 end")[0]
    assert detector.detect("dots 01.42.68.53.00 here")[0]
    assert detector.detect("intl +33 6 12 34 56 78 ok")[0]
    assert detector.detect("intl +33612345678 ok")[0]


def test_ignores_non_phone_digits():
    # A 9-digit SIREN must not be picked up as a phone number.
    assert detector.detect("SIREN 443061841 here") == []


def test_text_without_phone():
    assert detector.detect("no number here") == []
