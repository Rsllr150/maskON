"""Tests for the SIV (French licence plate) detector."""

from maskon.detectors.siv import SivDetector

detector = SivDetector()


def test_finds_hyphenated_siv():
    text = "Véhicule AB-123-CD garé"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "IMMAT"
    assert text[f.start : f.end] == "AB-123-CD"
    assert f.confidence == 0.8


def test_finds_spaced_siv():
    text = "AB 123 CD"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "AB 123 CD"


def test_rejects_mixed_separators():
    assert detector.detect("AB-123 CD") == []


def test_rejects_compact_form():
    assert detector.detect("AB123CD") == []


def test_rejects_lowercase():
    assert detector.detect("ab-123-cd") == []


def test_rejects_forbidden_letters():
    assert detector.detect("AI-123-CD") == []
    assert detector.detect("AB-123-OU") == []


def test_rejects_zero_digit_block():
    assert detector.detect("AB-000-CD") == []


def test_rejects_embedded_tokens():
    assert detector.detect("XAB-123-CD") == []
    assert detector.detect("AB-123-CDE") == []


def test_rejects_old_fni_format():
    assert detector.detect("123 AB 45") == []


def test_text_without_plate():
    assert detector.detect("Hello, nothing here.") == []
