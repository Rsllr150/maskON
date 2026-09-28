"""Normalise Unicode before detection, keeping a map back to the original.

Grouped PII written with NBSP, thin spaces, zero-widths or combining marks
would otherwise miss every format regex. We clean one character at a time
(NFKC, then drop format and non-spacing marks) so the result does not depend
on how the string is sliced, and we record the source index of every kept
code point. Findings and masking always use those original offsets.
"""

import unicodedata


def _is_ignored(ch: str) -> bool:
    return unicodedata.category(ch) in {"Cf", "Mn"}


def normalize(text: str) -> tuple[str, list[int]]:
    # ASCII holds no Cf/Mn and is its own NFKC form: skip the per-character
    # walk on the common case (it cost a third of redact() on 1 MB of logs).
    if text.isascii():
        return text, list(range(len(text) + 1))
    chars: list[str] = []
    offsets: list[int] = []
    for index, ch in enumerate(text):
        if _is_ignored(ch):
            continue
        for produced in unicodedata.normalize("NFKC", ch):
            if _is_ignored(produced):
                continue
            chars.append(produced)
            offsets.append(index)
    offsets.append(len(text))
    return "".join(chars), offsets
