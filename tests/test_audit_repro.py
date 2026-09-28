"""Non-regression: the "Reproduire les constats" commands of AUDIT.md (§1)
must no longer leak or crash."""

import maskon


def test_s1_merge_does_not_release_the_email():
    out = maskon.redact("443061841.contact@example.com")
    assert "contact" not in out
    assert "example" not in out


def test_s1_merge_does_not_release_the_phone_digits():
    out = maskon.redact("06 12 34 56 78jean@example.com")
    assert not any(c.isdigit() for c in out)
