"""Tests for the NIR detector — written before the implementation (TDD)."""

from maskon.detectors.nir import NirDetector

detector = NirDetector()


def test_finds_a_spaced_nir():
    text = "NIR 2 55 08 33 521 088 27 du dossier"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "NIR"
    assert text[f.start : f.end] == "2 55 08 33 521 088 27"
    assert f.confidence == 1.0


def test_finds_a_compact_nir():
    text = "secu 180017512345660 fin"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "180017512345660"


def test_finds_corsica_nir():
    text = "corse 1 80 12 2A 116 001 85 ok"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "1 80 12 2A 116 001 85"


def test_ignores_bad_checksum():
    text = "faux 253088123456789 ici"
    assert detector.detect(text) == []


def test_text_without_nir():
    assert detector.detect("nothing relevant here") == []
