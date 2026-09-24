"""Tests for the SPI control-key checksum — written BEFORE the implementation (TDD)."""

from maskon.detectors.validators.cle_spi import cle_spi


def test_valid_spi_keys():
    assert cle_spi("0123456789211") is True
    assert cle_spi("1234567890066") is True


def test_invalid_spi_keys():
    # Right shape (13 digits) but wrong control key → rejected.
    assert cle_spi("0123456789212") is False


def test_input_robustness():
    assert cle_spi("") is False
    assert cle_spi("012345678921") is False
