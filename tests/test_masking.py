"""Tests for the masking layer — pure text rewriting, written before the impl."""

from maskon.masking.apply import apply_mask
from maskon.masking.strategies import label
from maskon.models import Finding


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


def test_partial_keeps_edges():
    from maskon.masking.strategies import partial

    text = "IBAN FR7630006000011234567890189 end"
    findings = [Finding("IBAN", 5, 32, 1.0)]
    assert apply_mask(text, findings, partial) == "IBAN FR76****189 end"
