"""Run MaskON over the corpus and aggregate metrics.

Produces per-type and overall scores, plus the list of false positives so the
README can show them openly ("here are the cases I get wrong").
"""

from collections.abc import Iterable
from dataclasses import dataclass

from maskon.evaluation.metrics import Score, tally
from maskon.evaluation.models import AnnotatedExample
from maskon.service.redaction import RedactionService


@dataclass
class FalsePositive:
    type: str
    excerpt: str  # the text MaskON wrongly flagged


@dataclass
class EvaluationResult:
    per_type: dict[str, Score]
    overall: Score
    false_positives: list[FalsePositive]


def _total(scores: Iterable[Score]) -> Score:
    acc = Score()
    for score in scores:
        acc = acc + score
    return acc


def evaluate(
    examples: list[AnnotatedExample], service: RedactionService
) -> EvaluationResult:
    per_type: dict[str, Score] = {}
    false_positives: list[FalsePositive] = []

    for example in examples:
        predicted = service.detect(example.text)
        gold_keys = {(s.type, s.start, s.end) for s in example.spans}

        for finding in predicted:
            if (finding.type, finding.start, finding.end) not in gold_keys:
                excerpt = example.text[finding.start : finding.end]
                false_positives.append(FalsePositive(finding.type, excerpt))

        for pii_type, score in tally(example.spans, predicted).items():
            per_type[pii_type] = per_type.get(pii_type, Score()) + score

    return EvaluationResult(per_type, _total(per_type.values()), false_positives)
