"""Units and properties for Unicode normalisation before detection."""

import hypothesis.strategies as st
import pytest
from hypothesis import given, settings

from maskon.masking.strategies import hash_strategy
from maskon.normalize import normalize
from maskon.service.redaction import RedactionService
from tests.test_properties import VALID_PII

_STRIPPED = [
    "\u200b",  # ZERO WIDTH SPACE (Cf)
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE / BOM (Cf)
    "\u00ad",  # SOFT HYPHEN (Cf)
    "\u0301",  # COMBINING ACUTE ACCENT (Mn)
    "\ufe0f",  # VARIATION SELECTOR-16 (Mn)
]
_INVISIBLES = [
    "\u200b",
    "\u200c",
    "\u200d",
    "\ufeff",
    "\u00ad",
    "\u0301",
    "\u0338",
    "\ufe0f",
]
_UNICODE_SPACES = ["\u00a0", "\u202f", "\u2009"]
_HASH_KEY = b"property-key-0123456789"


@pytest.mark.parametrize("junk", _STRIPPED)
def test_stripped_characters_leave_correct_offsets(junk: str):
    text = f"a{junk}b"
    out, offsets = normalize(text)
    assert out == "ab"
    assert offsets == [0, 2, 3]


def test_ellipsis_expands_to_three_dots_sharing_one_offset():
    out, offsets = normalize("\u2026")
    assert out == "..."
    assert offsets == [0, 0, 0, 1]


@pytest.mark.parametrize("space", _UNICODE_SPACES)
def test_unicode_spaces_become_ascii_space(space: str):
    out, offsets = normalize(f"a{space}b")
    assert out == "a b"
    assert offsets == [0, 1, 2, 3]


def test_fullwidth_digits_become_ascii():
    out, offsets = normalize("\uff10\uff11\uff12")
    assert out == "012"
    assert offsets == [0, 1, 2, 3]


def test_offsets_end_with_the_len_sentinel():
    text = "ab"
    out, offsets = normalize(text)
    assert len(offsets) == len(out) + 1
    assert offsets[-1] == len(text)


def test_empty_text_is_empty_with_a_zero_sentinel():
    assert normalize("") == ("", [0])


def test_ascii_is_unchanged_with_identity_offsets():
    text = "Hello 06 12"
    out, offsets = normalize(text)
    assert out == text
    assert offsets == list(range(len(text) + 1))


@given(a=st.text(), b=st.text())
@settings(max_examples=300)
def test_normalize_is_concatenative(a: str, b: str):
    assert normalize(a + b)[0] == normalize(a)[0] + normalize(b)[0]


def _dirty_pii(pii: str, inserts: list[tuple[int, str]], spaces: list[str]) -> str:
    chars: list[str] = []
    space_i = 0
    for ch in pii:
        if ch == " " and space_i < len(spaces):
            chars.append(spaces[space_i])
            space_i += 1
        else:
            chars.append(ch)
    for pos, junk in sorted(
        ((min(max(pos, 0), len(chars)), junk) for pos, junk in inserts),
        reverse=True,
    ):
        chars.insert(pos, junk)
    return "".join(chars)


@given(
    pii=st.sampled_from(VALID_PII),
    inserts=st.lists(
        st.tuples(st.integers(min_value=0, max_value=80), st.sampled_from(_INVISIBLES)),
        max_size=12,
    ),
    spaces=st.lists(st.sampled_from(_UNICODE_SPACES), max_size=20),
)
@settings(max_examples=300)
def test_invisible_noise_does_not_hide_a_valid_pii(
    pii: str, inserts: list[tuple[int, str]], spaces: list[str]
):
    texte = _dirty_pii(pii, inserts, spaces)
    findings = RedactionService().detect(texte)
    normalized, offsets = normalize(texte)
    assert normalized
    # A2: a deleted character on the border stays outside; one in the middle
    # is covered. For a PII that fills the normalised string, that remaps to
    # (0, len) when the invisible characters are not on the edges.
    expected = (offsets[0], offsets[len(normalized) - 1] + 1)
    assert any((f.start, f.end) == expected for f in findings)
    redacted, _ = RedactionService().redact(texte)
    assert not {ch for ch in pii if ch.isdigit()} & set(redacted)


def test_hash_of_nbsp_phone_matches_ascii_and_direct_hash():
    service = RedactionService(hash_key=_HASH_KEY)
    ascii_phone = "06 12 34 56 78"
    nbsp_phone = "06\u00a012\u00a034\u00a056\u00a078"
    hashed_ascii, _ = service.redact(ascii_phone, mask="hash")
    hashed_nbsp, _ = service.redact(nbsp_phone, mask="hash")
    direct = hash_strategy(_HASH_KEY)(ascii_phone, "TEL")
    assert hashed_ascii == hashed_nbsp == direct
