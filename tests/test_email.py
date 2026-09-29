"""Tests for the EMAIL detector — written before the implementation (TDD)."""

import re
import time

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


def test_eighty_local_chars_is_a_single_untrimmed_finding():
    text = "a" * 80 + "@example.com"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert (findings[0].start, findings[0].end) == (0, 92)


def test_long_local_part_keeps_the_tail_and_caps_at_254():
    text = "a" * 300 + "@example.com"
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.end - f.start == 254
    assert f.end == len(text)
    assert text[f.start : f.end] == text[-254:]


def test_long_domain_shrinks_local_part_to_fit_254():
    domain = "x" * 196 + ".com"
    text = "a" * 100 + "@" + domain
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.end - f.start == 254
    assert text[f.start : f.end] == "a" * 53 + "@" + domain


def test_domain_overflow_after_one_local_char_emits_254_from_start():
    text = "x@example.com" + "y" * 242
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.start == 0
    assert f.end - f.start == 254


def test_domain_overflow_after_named_local_emits_254_from_start():
    text = "jean.dupont@example.com" + "x" * 300
    findings = detector.detect(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.start == 0
    assert f.end - f.start == 254


def test_space_stops_domain_before_padding():
    text = "jean.dupont@example.com " + "x" * 300
    findings = detector.detect(text)
    assert len(findings) == 1
    assert text[findings[0].start : findings[0].end] == "jean.dupont@example.com"


def test_two_adjacent_emails_are_two_findings():
    text = "a@b.com c@d.fr"
    findings = detector.detect(text)
    assert len(findings) == 2
    assert text[findings[0].start : findings[0].end] == "a@b.com"
    assert text[findings[1].start : findings[1].end] == "c@d.fr"


# On texts shorter than max_len the linear matcher still agrees with the
# unbounded shape regex: the 254 bound cannot apply (max_size=40).
@settings(max_examples=2000)
@given(st.text(alphabet="aZ9._%+-@. x!", max_size=40))
def test_linear_matcher_equals_plain_finditer(text: str):
    expected = [m.span() for m in re.compile(_EMAIL).finditer(text)]
    assert [(f.start, f.end) for f in detector.detect(text)] == expected


@settings(max_examples=2000)
@given(st.text(alphabet="a.@-0123456789", max_size=1000))
def test_no_finding_exceeds_max_len(text: str):
    leak_a = "x@example.com" + "y" * 242
    leak_b = "jean.dupont@example.com" + "x" * 300
    for sample in (text, leak_a + "@example", leak_b + "@example"):
        for f in detector.detect(sample):
            assert f.end - f.start <= EmailDetector.max_len


def test_one_megabyte_without_at_is_fast():
    text = "a" * 1_000_000
    start = time.perf_counter()
    detector.detect(text)
    assert time.perf_counter() - start < 1.0


def test_one_megabyte_of_at_pairs_is_fast():
    text = "a@" * (1_000_000 // 2)
    start = time.perf_counter()
    detector.detect(text)
    assert time.perf_counter() - start < 1.0
