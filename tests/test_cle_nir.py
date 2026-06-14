"""Tests for the NIR control-key checksum — written before the impl (TDD)."""

from maskon.detectors.validators.cle_nir import cle_nir


def test_valid_nirs():
    assert cle_nir("255083352108827") is True
    assert cle_nir("180017512345660") is True


def test_tolerates_spaces():
    assert cle_nir("2 55 08 33 521 088 27") is True


def test_corsica_department_2a():
    # Department 2A (a letter) → handled in the checksum (2A → 19).
    assert cle_nir("180122A11600185") is True


def test_invalid_key():
    assert cle_nir("253088123456789") is False


def test_input_robustness():
    assert cle_nir("") is False
    assert cle_nir("123") is False  # wrong length
    assert cle_nir("18001751234566X") is False  # non-digit key
