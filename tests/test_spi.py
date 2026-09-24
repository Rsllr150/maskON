"""Tests for the SPI detector — written before the implementation (TDD)."""

from maskon.detectors.spi import SpiDetector

detector = SpiDetector()


def test_finds_a_valid_spi():
    text = "SPI 0123456789211 here"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "SPI"
    assert text[f.start : f.end] == "0123456789211"
    assert f.confidence == 1.0


def test_tolerates_spaces():
    text = "Number 01 23 456 789 211 valid"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "01 23 456 789 211"


def test_ignores_bad_key():
    # Right shape (13 digits) but wrong SPI key → not a SPI.
    text = "Invoice 0123456789212 this month"
    assert detector.detect(text) == []


def test_ignores_mixed_grouping():
    # Compact-or-grouped only: a mixed 4+9 split is not a SPI.
    assert detector.detect("0123 456789211") == []


def test_ignores_spi_inside_longer_digit_run():
    # A 14-digit run containing a valid 13-digit SPI must not match.
    assert detector.detect("00123456789211") == []


def test_text_without_spi():
    assert detector.detect("Hello, nothing here.") == []
