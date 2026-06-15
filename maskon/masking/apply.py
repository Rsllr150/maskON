"""Apply a masking strategy to text, given the findings to replace.

We build the result in a single left-to-right pass: walk the (non-overlapping)
findings in order, copy the text between them, and insert each mask. Offsets are
read from the original text, so positions never shift. This is O(n) — the naive
"rebuild the whole string per finding" approach is O(n²) and collapses on large
inputs (a bug found by benchmarking).
"""

from collections.abc import Callable

from maskon.models import Finding

# A strategy: (original_text, pii_type) -> replacement_text.
Strategy = Callable[[str, str], str]


def apply_mask(text: str, findings: list[Finding], strategy: Strategy) -> str:
    parts: list[str] = []
    cursor = 0
    for f in sorted(findings, key=lambda f: f.start):
        parts.append(text[cursor : f.start])
        parts.append(strategy(text[f.start : f.end], f.type))
        cursor = f.end
    parts.append(text[cursor:])
    return "".join(parts)
