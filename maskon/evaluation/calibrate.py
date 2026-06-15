"""Confidence calibration.

A detector's confidence is meant to be P(a finding is a real PII) — which is
exactly its precision. Detectors ship a hand-set prior (1.0 for checksum types,
lower for shape-only ones); this measures the real precision on the corpus so
the gap is visible and the priors can be tuned with evidence.

On a small corpus the measured numbers are indicative, not final — they should
guide a hand tune, not be blindly copied (that would overfit a few examples).
"""

from dataclasses import dataclass

from maskon.evaluation.evaluate import evaluate
from maskon.evaluation.models import AnnotatedExample
from maskon.service.redaction import RedactionService


@dataclass
class Calibration:
    pii_type: str
    declared: float  # the detector's hand-set confidence
    measured: float  # precision measured on the corpus
    support: int  # number of predictions backing the measure (tp + fp)


def calibrate(
    examples: list[AnnotatedExample], service: RedactionService
) -> list[Calibration]:
    result = evaluate(examples, service)
    declared = {detector.type: detector.confidence for detector in service.detectors}
    return [
        Calibration(
            pii_type=pii_type,
            declared=declared.get(pii_type, float("nan")),
            measured=score.precision,
            support=score.tp + score.fp,
        )
        for pii_type, score in sorted(result.per_type.items())
    ]
