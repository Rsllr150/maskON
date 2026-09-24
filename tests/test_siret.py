"""Tests for the SIRET detector — written before the implementation (TDD)."""

from maskon.detectors.carte_bancaire import CarteBancaireDetector
from maskon.detectors.siren import SirenDetector
from maskon.detectors.siret import SiretDetector
from maskon.service.redaction import RedactionService

detector = SiretDetector()
service = RedactionService()


def test_finds_a_valid_siret():
    text = "SIRET 44306184100047 here"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "SIRET"
    assert text[f.start : f.end] == "44306184100047"
    assert f.confidence == 1.0


def test_tolerates_spaces():
    text = "SIRET 443 061 841 00047 valid"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "443 061 841 00047"


def test_ignores_bad_checksum():
    # Right shape (14 digits) but wrong Luhn key → not a SIRET.
    assert detector.detect("Ref 44306184100048 here") == []


def test_ignores_siret_whose_siren_is_invalid():
    # A Diners card: Luhn-valid on 14 digits, but its first 9 digits are not a
    # valid SIREN → not a SIRET.
    assert detector.detect("card 30569309025904") == []


def test_la_poste_exception():
    # La Poste establishments (SIREN 356000000) fail Luhn; their rule is
    # "sum of the digits is a multiple of 5".
    text = "SIRET 35600000009075"
    assert [f.type for f in detector.detect(text)] == ["SIRET"]
    assert detector.detect("SIRET 35600000009076") == []


def test_text_without_siret():
    assert detector.detect("Hello, nothing here.") == []


# --- Service level: the two reported bugs, and no regression on SIREN / CB ---


def test_compact_siret_is_labelled_siret_not_cb():
    redacted, _ = service.redact("SIRET 44306184100047 fin", mask="label")
    assert redacted == "SIRET [SIRET] fin"


def test_spaced_siret_is_masked_whole():
    # Used to leak the last 5 digits (only the SIREN part was matched).
    redacted, _ = service.redact("SIRET 443 061 841 00047 fin", mask="label")
    assert redacted == "SIRET [SIRET] fin"


def test_siret_wins_regardless_of_detector_order():
    # The CB/SIRET tie is resolved by the merge, not by registration order.
    reversed_service = RedactionService(
        detectors=[CarteBancaireDetector(), SirenDetector(), SiretDetector()]
    )
    redacted, _ = reversed_service.redact("n 44306184100047", mask="label")
    assert redacted == "n [SIRET]"


def test_invalid_nic_keeps_the_siren_only():
    # Not a proven SIRET: the valid SIREN is masked, the rest is left as is.
    redacted, _ = service.redact("n 443 061 841 12345", mask="label")
    assert redacted == "n [SIREN] 12345"


def test_siren_and_card_unchanged():
    redacted, _ = service.redact(
        "SIREN 443061841, carte 4111111111111111, diners 30569309025904",
        mask="label",
    )
    assert redacted == "SIREN [SIREN], carte [CB], diners [CB]"


def test_two_adjacent_sirens_are_not_a_siret():
    redacted, _ = service.redact("443061841 552032534", mask="label")
    assert redacted == "[SIREN] [SIREN]"


def test_mixed_spacing_is_not_a_siret():
    # Compact SIREN + space + amount: only compact or 3-3-3-5 is a SIRET.
    redacted, _ = service.redact("SIREN 443061841 10004 euros", mask="label")
    assert redacted == "SIREN [SIREN] 10004 euros"
    assert detector.detect("SIREN 443 06184100047") == []
