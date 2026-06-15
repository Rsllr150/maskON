"""Tests for confidence calibration."""

from maskon.evaluation.calibrate import calibrate
from maskon.evaluation.models import AnnotatedExample, GoldSpan
from maskon.service.redaction import RedactionService


def test_calibrate_reports_declared_and_measured():
    examples = [
        AnnotatedExample("mail a@b.com", [GoldSpan("EMAIL", 5, 12)]),  # a true email
        AnnotatedExample("ref 0123456789 x", []),  # flagged TEL, but not real
    ]
    by_type = {c.pii_type: c for c in calibrate(examples, RedactionService())}

    # EMAIL: 1 correct prediction, 0 wrong → precision 1.0; prior is 0.9.
    assert by_type["EMAIL"].measured == 1.0
    assert by_type["EMAIL"].declared == 0.9

    # TEL: 0 correct, 1 wrong → precision 0.0 on a support of 1 prediction.
    assert by_type["TEL"].measured == 0.0
    assert by_type["TEL"].support == 1
    assert by_type["TEL"].declared == 0.7
