"""Tests for the masking layer — pure text rewriting, written before the impl."""

import re

import pytest

from maskon.masking.apply import apply_mask
from maskon.masking.strategies import (
    WeakHashKey,
    build_strategies,
    hash_strategy,
    label,
    partial,
)
from maskon.models import Finding

KEY = b"0123456789abcdef"


def test_label_replaces_one_finding():
    text = "IBAN FR7630006000011234567890189 end"
    findings = [Finding("IBAN", 5, 32, 1.0)]
    assert apply_mask(text, findings, label) == "IBAN [IBAN] end"


def test_label_replaces_several_findings():
    text = "tel 0612345678 mail a@b.com"
    findings = [
        Finding("TEL", 4, 14, 0.7),
        Finding("EMAIL", 20, 27, 0.9),
    ]
    assert apply_mask(text, findings, label) == "tel [TEL] mail [EMAIL]"


def test_positions_stay_correct_when_lengths_differ():
    # The first finding is much longer than its mask; the second must still
    # land on the right characters → proves right-to-left replacement.
    text = "a FR7630006000011234567890189 b 0612345678 c"
    findings = [
        Finding("IBAN", 2, 29, 1.0),
        Finding("TEL", 32, 42, 0.7),
    ]
    assert apply_mask(text, findings, label) == "a [IBAN] b [TEL] c"


def test_no_findings_returns_text_unchanged():
    assert apply_mask("nothing here", [], label) == "nothing here"


def test_partial_iban_keeps_the_country_and_the_last_four():
    text = "IBAN FR7630006000011234567890189 end"
    findings = [Finding("IBAN", 5, 32, 1.0)]
    assert apply_mask(text, findings, partial) == "IBAN FR****0189 end"


@pytest.mark.parametrize(
    ("value", "pii_type", "expected"),
    [
        # PCI-DSS: at most the first 6 and the last 4, from 16 digits up.
        ("4111 1111 1111 1111", "CB", "411111****1111"),
        ("4111-1111-1111-1111", "CB", "411111****1111"),
        ("378282246310005", "CB", "****0005"),  # 15 digits: last 4 only
        ("jean.dupont@example.com", "EMAIL", "j****@example.com"),
        ("06 12 34 56 78", "TEL", "****78"),
        ("FR76 3000 6000 0112 3456 7890 189", "IBAN", "FR****0189"),
        # Short identifiers: any edge makes them guessable → nothing shown.
        ("732829320", "SIREN", "****"),
        ("73282932000074", "SIRET", "****"),
        ("1 84 12 75 108 234 56", "NIR", "****"),
        ("1000000021104", "SPI", "****"),
        ("12AB34567", "PASSEPORT", "****"),
        ("AB-123-CD", "IMMAT", "****"),
        ("FR44732829320", "TVA", "****"),
        ("anything", "UNKNOWN", "****"),  # fail-closed default
    ],
)
def test_partial_shows_only_what_the_type_allows(value, pii_type, expected):
    assert partial(value, pii_type) == expected


def test_hash_is_deterministic_typed_and_versioned():
    h = hash_strategy(KEY)
    token = h("FR7630006000011234567890189", "IBAN")
    assert token == h("FR7630006000011234567890189", "IBAN")  # same value, same token
    assert re.fullmatch(r"iban_v1_[0-9a-f]{16}", token)  # 64 bits, versioned
    assert h("DIFFERENT", "IBAN") != token  # different value, different token


def test_hash_carries_the_key_version():
    assert hash_strategy(KEY, "v2")("v", "EMAIL").startswith("email_v2_")


def test_hash_depends_on_the_key():
    # HMAC, not a plain hash: changing the key changes the token.
    token_a = hash_strategy(b"key-a" * 4)("v", "EMAIL")
    token_b = hash_strategy(b"key-b" * 4)("v", "EMAIL")
    assert token_a != token_b


def test_a_key_shorter_than_16_bytes_is_refused():
    with pytest.raises(WeakHashKey, match="at least 16 bytes"):
        build_strategies(b"a" * 15)
    assert "hash" in build_strategies(b"a" * 16)


def test_a_malformed_key_version_is_refused():
    with pytest.raises(ValueError, match="version"):
        build_strategies(KEY, "v1_bad")
