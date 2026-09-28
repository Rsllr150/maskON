"""EMAIL detector.

No checksum exists for an email address, so detection is pure shape (regex).
The pattern is the pragmatic, widely-used one — not the full RFC 5322 grammar,
which is impractical and matches almost nothing extra in real text.

Linear time. A plain `finditer` is quadratic here: on a long run of local-part
characters with no `@`, it restarts the scan from every position of the run
(12 KB took 285 ms, 1 MB ~45 min). `_matches` finds exactly the same matches
while trying each run once — see its docstring for why nothing is lost.
"""

import re
from collections.abc import Iterator

from maskon.detectors.base import Detector

_LOCAL = r"[A-Za-z0-9._%+-]"
_EMAIL = rf"{_LOCAL}+@[A-Za-z0-9.-]+\.[A-Za-z]{{2,}}"


class EmailDetector(Detector):
    type = "EMAIL"
    confidence = 0.9  # no checksum, but the shape is highly distinctive
    _pattern = re.compile(_EMAIL)
    # Same shape, but only allowed to start at the beginning of a local run.
    _at_run_start = re.compile(rf"(?<!{_LOCAL}){_EMAIL}")

    def _matches(self, text: str) -> Iterator[re.Match[str]]:
        """Same matches as `_pattern.finditer`, in linear time.

        The local part ends at the first non-local character, so a match that
        starts inside a run of local characters also matches from the run's
        first character, with the same end. Leftmost-first matching therefore
        only ever starts a match at `pos` (where the previous one ended, which
        may be mid-run) or at the start of a run. We try `pos` once, then
        search only run starts: each character is scanned a bounded number
        of times.
        """
        pos = 0
        while pos < len(text):
            match = self._pattern.match(text, pos) or self._at_run_start.search(
                text, pos + 1
            )
            if match is None:
                return
            yield match
            pos = match.end()
