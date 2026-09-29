"""EMAIL detector.

No checksum exists for an email address, so detection is pure shape (regex).
The pattern is the pragmatic, widely-used one — not the full RFC 5322 grammar,
which is impractical and matches almost nothing extra in real text.

An email is at most 254 characters. For each `@`, the local part is the run
of `_LOCAL` characters that immediately precedes it, limited to its last 253
so a longer run keeps the tail glued to `@`, never the head. The domain keeps
the usual `[A-Za-z0-9.-]+.[A-Za-z]{2,}` shape. If local + `@` + domain would
exceed 254, the local part is shortened from the left (down to 1 character)
to fit; if the domain itself still overflows, it is truncated by matching
with `endpos = start + 254`. A `@` whose bounded form still matches (a `.`
and at least two TLD letters in the window) always emits — fail-closed.

Linear time. A plain `finditer` is quadratic here: on a long run of local-part
characters with no `@`, it restarts the scan from every position of the run
(12 KB took 285 ms, 1 MB ~45 min). Putting `{1,253}` on the local part would
reintroduce that. `_matches` instead scans once for each `@`, walks back at
most 253 local characters, then matches the domain inside a 254-character
window.
"""

import re
from collections.abc import Iterator

from maskon.detectors.base import Detector

_LOCAL = r"[A-Za-z0-9._%+-]"
_LOCAL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-"
)
_DOMAIN = r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
_DOMAIN_START_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-"
)
_EMAIL = rf"{_LOCAL}+@{_DOMAIN}"
_DOMAIN_RE = re.compile(_DOMAIN)


class EmailDetector(Detector):
    type = "EMAIL"
    confidence = 0.9  # no checksum, but the shape is highly distinctive
    _pattern = re.compile(_EMAIL)
    max_len = 254

    def _matches(self, text: str) -> Iterator[re.Match[str]]:
        """Bounded email matches, leftmost-first, in linear time.

        Each `@` is considered once. The local part is the `_LOCAL` run
        immediately before it, at least 1 character, capped at its last
        253 (and shortened further so the whole address is at most
        `max_len`). If the domain still overflows, `_pattern.match`
        truncates it with `endpos`. The next `@` is sought after the
        previous match ends, so matches do not overlap.
        """
        # Domain always contains a '.'. One C-level scan avoids visiting every
        # `@` on traps like 1 MB of "a@".
        if "." not in text:
            return
        pos = 0
        max_len = self.max_len
        n = len(text)
        while True:
            at = text.find("@", pos)
            if at < 0:
                return
            # One-char rejects before any regex: local run glued to `@`, and a
            # domain that can still contain a '.' inside the 254-char window.
            if at == pos or text[at - 1] not in _LOCAL_CHARS:
                pos = at + 1
                continue
            if at + 1 >= n or text[at + 1] not in _DOMAIN_START_CHARS:
                pos = at + 1
                continue
            window_end = at + max_len
            if text.find(".", at + 1, window_end) < 0:
                next_dot = text.find(".", window_end)
                if next_dot < 0:
                    return
                pos = max(at + 1, next_dot - (max_len - 1))
                continue
            floor = max(pos, at - (max_len - 1))
            local_start = at - 1
            while local_start > floor and text[local_start - 1] in _LOCAL_CHARS:
                local_start -= 1
            domain = _DOMAIN_RE.match(text, at + 1)
            if domain is None:
                pos = at + 1
                continue
            domain_len = domain.end() - (at + 1)
            max_local = max_len - 1 - domain_len
            if max_local >= 1:
                if at - local_start > max_local:
                    local_start = at - max_local
            match = self._pattern.match(text, local_start, local_start + max_len)
            if match is None and max_local < 1 and local_start < at - 1:
                match = self._pattern.match(text, at - 1, at - 1 + max_len)
            if match is None:
                pos = at + 1
                continue
            yield match
            pos = match.end()
