"""Apply a masking strategy to text, given the findings to replace.

The applier owns the tricky part: replacing a span changes the text length, so
every later position would shift. We avoid that by replacing from RIGHT to LEFT
— once we touch a span, only characters after it move, and those are already done.
"""

from collections.abc import Callable

from maskon.models import Finding

# A strategy: (original_text, pii_type) -> replacement_text.
Strategy = Callable[[str, str], str]


def apply_mask(text: str, findings: list[Finding], strategy: Strategy) -> str:
    # Right to left: highest start first, so untouched positions stay valid.
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        replacement = strategy(text[f.start:f.end], f.type)
        text = text[:f.start] + replacement + text[f.end:]
    return text
