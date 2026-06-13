"""Tests for the Luhn checksum — written BEFORE the implementation (TDD)."""

from maskon.detectors.validators.luhn import luhn


def test_valid_sirens():
    # Real SIREN numbers that must pass the Luhn key.
    assert luhn("443061841") is True  # Google France
    assert luhn("552032534") is True  # Danone


def test_invalid_sirens():
    # Right shape (9 digits) but wrong control key → rejected.
    assert luhn("443061842") is False
    assert luhn("123456789") is False


def test_input_robustness():
    # A non-numeric string is not a valid number.
    assert luhn("") is False
    assert luhn("abc") is False
