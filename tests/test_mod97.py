"""Tests for the IBAN mod-97 checksum (ISO 7064) — written before the impl (TDD)."""

from maskon.detectors.validators.mod97 import mod97


def test_valid_ibans():
    # Real IBANs that must pass the mod-97 check.
    assert mod97("FR7630006000011234567890189") is True  # France
    assert mod97("DE89370400440532013000") is True  # Germany
    assert mod97("GB82WEST12345698765432") is True  # UK, contains letters


def test_tolerates_spaces_and_case():
    # The validator normalizes spacing and case itself.
    assert mod97("FR76 3000 6000 0112 3456 7890 189") is True
    assert mod97("fr7630006000011234567890189") is True


def test_invalid_checksum():
    # One digit changed at the end → checksum fails.
    assert mod97("FR7630006000011234567890188") is False


def test_input_robustness():
    assert mod97("") is False
    assert mod97("not an iban") is False
