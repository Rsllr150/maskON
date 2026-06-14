"""Ground-truth data for evaluation.

A `GoldSpan` is a PII span annotated BY HAND — what a human knows is a PII,
independent of what the detectors produce. That independence is what makes the
measured metrics meaningful.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class GoldSpan:
    type: str
    start: int
    end: int


@dataclass
class AnnotatedExample:
    text: str
    spans: list[GoldSpan]
