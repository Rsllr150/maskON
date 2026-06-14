"""Tests for the overlap-merging logic — pure, written before the impl (TDD)."""

from maskon.models import Finding
from maskon.service.merge import merge_overlapping


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
