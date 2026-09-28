"""Non-regression: the "Reproduire les constats" commands of AUDIT.md (§1, §3,
§4, §5, §9) must no longer leak or crash."""

import re

import pytest

import maskon
from maskon.masking.strategies import WeakHashKey

KEY = b"audit-key-0123456789"


def test_s1_merge_does_not_release_the_email():
    out = maskon.redact("443061841.contact@example.com")
    assert "contact" not in out
    assert "example" not in out


def test_s1_merge_does_not_release_the_phone_digits():
    out = maskon.redact("06 12 34 56 78jean@example.com")
    assert not any(c.isdigit() for c in out)


def test_s3_nbsp_phone_is_masked():
    assert maskon.redact("06\u00a012\u00a034\u00a056\u00a078") == "[TEL]"


def test_s3_narrow_nbsp_iban_is_masked():
    assert (
        maskon.redact("FR76\u202f3000\u202f6000\u202f0112\u202f3456\u202f7890\u202f189")
        == "[IBAN]"
    )


def test_s3_nbsp_iban_is_masked():
    assert (
        maskon.redact("FR76\u00a03000\u00a06000\u00a00112\u00a03456\u00a07890\u00a0189")
        == "[IBAN]"
    )


def test_s3_zero_width_in_email_is_masked():
    assert maskon.redact("jean\u200b@example.com") == "[EMAIL]"


def test_s3_combining_mark_on_phone_is_masked():
    assert maskon.redact("0\u03016 12 34 56 78") == "[TEL]"


def test_s4_an_endless_iban_shape_does_not_crash():
    maskon.redact("FR76 " + "1234 " * 1200)


def test_s4_a_real_iban_is_still_masked():
    assert maskon.redact("FR76 3000 6000 0112 3456 7890 189") == "[IBAN]"


def test_s5_partial_hides_a_siren_entirely():
    assert maskon.redact("732829320", mask="partial") == "****"


def test_s9_hash_is_64_bits_and_versioned():
    out = maskon.redact("FR7630006000011234567890189", mask="hash", hash_key=KEY)
    assert re.fullmatch(r"iban_v1_[0-9a-f]{16}", out)


def test_s9_the_key_version_is_configurable(monkeypatch):
    out = maskon.redact("a@b.com", mask="hash", hash_key=KEY, hash_key_version="v2")
    assert out.startswith("email_v2_")
    monkeypatch.setenv("MASKON_HASH_KEY_VERSION", "v3")
    assert maskon.redact("a@b.com", mask="hash", hash_key=KEY).startswith("email_v3_")


def test_s9_a_short_key_is_refused_at_construction(monkeypatch):
    # Refused even for `label`: a weak key is a misconfiguration, not a detail.
    with pytest.raises(WeakHashKey):
        maskon.redact("a@b.com", hash_key=b"a")
    monkeypatch.setenv("MASKON_HASH_KEY", "short")
    with pytest.raises(WeakHashKey):
        maskon.redact("a@b.com")
