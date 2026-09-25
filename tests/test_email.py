"""Tests for the EMAIL detector — written before the implementation (TDD)."""

import re

import hypothesis.strategies as st
from hypothesis import given, settings

from maskon.detectors.email import _EMAIL, EmailDetector

detector = EmailDetector()


def test_finds_a_simple_email():
    text = "Write to jean.dupont@example.com today"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "EMAIL"
    assert text[f.start : f.end] == "jean.dupont@example.com"
    # No checksum exists for emails → confidence below 1.0.
    assert f.confidence < 1.0


def test_finds_email_with_plus_and_subdomains():
    text = "alias a.b+tag@mail.example.co.uk works"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "a.b+tag@mail.example.co.uk"


def test_finds_two_emails():
    text = "a@b.com and c@d.org"
    assert len(detector.detect(text)) == 2


def test_text_without_email():
    assert detector.detect("no address here, just @ and words") == []


# The linear matcher must find exactly what the plain regex finds. Small
# alphabet biased to the characters that make runs, dots and `@` interact.
@settings(max_examples=2000)
@given(st.text(alphabet="aZ9._%+-@. x!", max_size=40))
def test_linear_matcher_equals_plain_finditer(text: str):
    expected = [m.span() for m in re.compile(_EMAIL).finditer(text)]
    assert [(f.start, f.end) for f in detector.detect(text)] == expected
