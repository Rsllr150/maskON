"""Tests for the evaluation metrics — the heart of the corpus story."""

from maskon.evaluation.metrics import Score, tally
from maskon.evaluation.models import GoldSpan
from maskon.models import Finding


def test_score_precision_recall_f1():
    s = Score(tp=8, fp=2, fn=1)
    assert s.precision == 0.8
    assert round(s.recall, 3) == 0.889
    assert round(s.f1, 3) == 0.842


def test_score_handles_empty():
    empty = Score()
    assert empty.precision == 0.0
    assert empty.recall == 0.0
    assert empty.f1 == 0.0


def test_score_addition():
    assert Score(1, 2, 3) + Score(10, 20, 30) == Score(11, 22, 33)


def test_tally_perfect_match():
    gold = [GoldSpan("IBAN", 0, 10)]
    pred = [Finding("IBAN", 0, 10, 1.0)]
    scores = tally(gold, pred)
    assert scores["IBAN"] == Score(tp=1, fp=0, fn=0)


def test_tally_counts_false_positive_and_false_negative():
    gold = [GoldSpan("TEL", 5, 15)]  # a phone we should have caught
    pred = [Finding("SIREN", 0, 9, 1.0)]  # but we flagged something else
    scores = tally(gold, pred)
    assert scores["SIREN"].fp == 1  # predicted, not real
    assert scores["TEL"].fn == 1  # real, not predicted


def test_tally_boundary_mismatch_is_not_a_match():
    # One character off → not a true positive (exact matching is strict).
    gold = [GoldSpan("TEL", 0, 10)]
    pred = [Finding("TEL", 0, 11, 0.7)]
    scores = tally(gold, pred)
    assert scores["TEL"] == Score(tp=0, fp=1, fn=1)
