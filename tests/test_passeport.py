"""Tests for the PASSEPORT detector — written before the implementation (TDD)."""

from maskon.detectors.passeport import PasseportDetector

detector = PasseportDetector()


def test_finds_a_passport_number():
    text = "Passeport 12AB34567 délivré"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "PASSEPORT"
    assert text[f.start : f.end] == "12AB34567"
    assert f.confidence == 0.8


def test_rejects_lowercase():
    assert detector.detect("12ab34567") == []


def test_rejects_inner_space():
    assert detector.detect("12AB 34567") == []


def test_rejects_embedded_in_longer_token():
    assert detector.detect("X12AB34567") == []
    assert detector.detect("12AB345678") == []


def test_rejects_wrong_shape():
    assert detector.detect("1AB234567") == []


def test_text_without_passport():
    assert detector.detect("Hello, nothing here.") == []
