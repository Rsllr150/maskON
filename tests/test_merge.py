"""Tests for the overlap-merging logic — pure, written before the impl (TDD)."""

from maskon.detectors.carte_bancaire import CarteBancaireDetector
from maskon.detectors.spi import SpiDetector
from maskon.models import Finding
from maskon.service.merge import merge_overlapping
from maskon.service.redaction import RedactionService


def test_empty():
    assert merge_overlapping([]) == []


def test_keeps_disjoint_findings_sorted():
    # Two findings that don't touch → both kept, ordered by position.
    a = Finding("IBAN", 20, 47, 1.0)
    b = Finding("SIREN", 5, 14, 1.0)
    assert merge_overlapping([a, b]) == [b, a]


def test_overlap_keeps_higher_confidence():
    weak = Finding("TEL", 0, 10, 0.7)
    strong = Finding("IBAN", 2, 8, 1.0)
    assert merge_overlapping([weak, strong]) == [strong]


def test_overlap_equal_confidence_keeps_longer():
    short = Finding("X", 0, 5, 0.9)
    long = Finding("Y", 0, 12, 0.9)
    assert merge_overlapping([short, long]) == [long]


def test_finding_fully_inside_another_is_dropped():
    outer = Finding("IBAN", 0, 20, 1.0)
    inner = Finding("SIREN", 5, 14, 1.0)
    assert merge_overlapping([outer, inner]) == [outer]


def test_exact_tie_prefers_the_more_specific_type():
    # Same span, same confidence: SIRET beats CB, whatever the input order.
    cb = Finding("CB", 0, 14, 1.0)
    siret = Finding("SIRET", 0, 14, 1.0)
    assert merge_overlapping([cb, siret]) == [siret]
    assert merge_overlapping([siret, cb]) == [siret]


def test_exact_tie_prefers_spi_over_cb():
    # A 13-digit number valid as both SPI (mod 511) and CB (Luhn) is a SPI.
    cb = Finding("CB", 0, 13, 1.0)
    spi = Finding("SPI", 0, 13, 1.0)
    assert merge_overlapping([cb, spi]) == [spi]
    assert merge_overlapping([spi, cb]) == [spi]


def test_service_labels_spi_that_also_passes_luhn_as_spi():
    # End to end: 1000000021104 passes both the SPI key and the CB Luhn check.
    text = "Numéro fiscal 1000000021104 fin"
    # Premise: both detectors really fire on it, so the merge tie-break runs.
    assert CarteBancaireDetector().detect(text)
    assert SpiDetector().detect(text)
    redacted, _ = RedactionService().redact(text, mask="label")
    assert redacted == "Numéro fiscal [SPI] fin"


def test_service_detects_the_new_detectors():
    text = "SPI 01 23 456 789 211, passeport 12AB34567, plaque AB-123-CD."
    redacted, _ = RedactionService().redact(text, mask="label")
    assert redacted == "SPI [SPI], passeport [PASSEPORT], plaque [IMMAT]."
