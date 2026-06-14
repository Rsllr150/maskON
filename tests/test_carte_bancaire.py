"""Tests for the bank card detector — reuses the Luhn validator (TDD)."""

from maskon.detectors.carte_bancaire import CarteBancaireDetector

detector = CarteBancaireDetector()


def test_finds_spaced_card():
    text = "CB 4111 1111 1111 1111 expire 12/26"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "CB"
    assert text[f.start : f.end] == "4111 1111 1111 1111"
    assert f.confidence == 1.0


def test_finds_dashed_card():
    text = "paiement 5555-5555-5555-4444 ok"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "5555-5555-5555-4444"


def test_finds_compact_card():
    text = "carte 4012888888881881 enregistree"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "4012888888881881"


def test_ignores_bad_luhn():
    # 16 digits, right shape, but fails the Luhn checksum → not a card.
    text = "ref 4111111111111112 interne"
    assert detector.detect(text) == []


def test_text_without_card():
    assert detector.detect("nothing relevant here") == []
