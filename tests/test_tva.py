"""Tests for the TVA detector — written before the implementation (TDD)."""

from maskon.detectors.tva import TvaDetector
from maskon.service.redaction import RedactionService

detector = TvaDetector()
service = RedactionService()


def test_finds_a_valid_compact_tva():
    text = "FR64443061841"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "TVA"
    assert text[f.start : f.end] == "FR64443061841"
    assert f.confidence == 1.0


def test_finds_a_valid_grouped_tva():
    text = "FR 64 443 061 841"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "FR 64 443 061 841"


def test_other_valid_values():
    for value in ("FR27552032534", "FR40303265045"):
        findings = detector.detect(value)
        assert len(findings) == 1
        assert findings[0].type == "TVA"
        assert value[findings[0].start : findings[0].end] == value


def test_wrong_key():
    # Right SIREN, wrong 2-digit key → not a TVA.
    assert detector.detect("FR65443061841") == []


def test_right_key_but_siren_fails_luhn():
    # SIREN 443061842 fails Luhn; its key is (12 + 3 * (443061842 % 97)) % 97
    # = 67. Shape and key formula are right; the SIREN proof is not.
    assert detector.detect("FR67443061842") == []


def test_la_poste_is_detected():
    # La Poste SIREN 356000000 passes Luhn; key is 39. Detected like any other.
    text = "FR39356000000"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "TVA"
    assert text[f.start : f.end] == text


def test_lowercase_rejected():
    assert detector.detect("fr64443061841") == []


def test_mixed_grouping_rejected():
    assert detector.detect("FR64 443061841") == []
    assert detector.detect("FR 64443061841") == []


def test_word_boundaries():
    # Inside a longer run of digits, or prefixed by a letter: \b must fail.
    assert detector.detect("FR644430618412") == []
    assert detector.detect("XFR64443061841") == []


def test_lowercase_full_number_not_detected():
    assert detector.detect("fr64443061841") == []


def test_wrong_grouping_not_detected():
    assert detector.detect("FR 644 430 618 41") == []


def test_glued_to_digits_not_detected():
    assert detector.detect("FR644430618411") == []


def test_key_00_not_matching_siren_not_detected():
    assert detector.detect("FR00443061841") == []


def test_text_without_tva():
    assert detector.detect("Hello, nothing here.") == []


# --- Service level: whole-number mask, and no regression on IBAN ---


def test_grouped_tva_is_masked_whole_not_siren():
    redacted, _ = service.redact("TVA FR 64 443 061 841 fin", mask="label")
    assert redacted == "TVA [TVA] fin"


def test_iban_is_still_iban():
    redacted, _ = service.redact(
        "FR76 3000 6000 0112 3456 7890 189",
        mask="label",
    )
    assert redacted == "[IBAN]"
