"""Non-regression: the "Reproduire les constats" commands of AUDIT.md (§1, §4)
must no longer leak or crash."""

import maskon


def test_s1_merge_does_not_release_the_email():
    out = maskon.redact("443061841.contact@example.com")
    assert "contact" not in out
    assert "example" not in out


def test_s1_merge_does_not_release_the_phone_digits():
    out = maskon.redact("06 12 34 56 78jean@example.com")
    assert not any(c.isdigit() for c in out)


def test_s4_an_endless_iban_shape_does_not_crash():
    maskon.redact("FR76 " + "1234 " * 1200)


def test_s4_a_real_iban_is_still_masked():
    assert maskon.redact("FR76 3000 6000 0112 3456 7890 189") == "[IBAN]"
