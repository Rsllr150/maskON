"""Precision / recall / F1 over exact span matches.

A predicted finding counts as a true positive only if a gold span has the same
(type, start, end). Exact matching is strict on purpose: it surfaces off-by-one
boundary bugs instead of hiding them.
"""

from collections import defaultdict
from dataclasses import dataclass

from maskon.evaluation.models import GoldSpan
from maskon.models import Finding

SpanKey = tuple[str, int, int]


@dataclass
class Score:
    tp: int = 0  # true positives: real PII we caught
    fp: int = 0  # false positives: we flagged something that wasn't PII
    fn: int = 0  # false negatives: real PII we missed

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def __add__(self, other: "Score") -> "Score":
        return Score(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)


def tally(gold: list[GoldSpan], predicted: list[Finding]) -> dict[str, Score]:
    gold_keys: set[SpanKey] = {(g.type, g.start, g.end) for g in gold}
    pred_keys: set[SpanKey] = {(f.type, f.start, f.end) for f in predicted}

    scores: defaultdict[str, Score] = defaultdict(Score)
    for key in gold_keys & pred_keys:
        scores[key[0]].tp += 1
    for key in pred_keys - gold_keys:
        scores[key[0]].fp += 1
    for key in gold_keys - pred_keys:
        scores[key[0]].fn += 1
    return dict(scores)
