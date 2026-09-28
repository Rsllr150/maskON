"""Base class shared by every detector.

A detector scans text with a regex, optionally validates each candidate, and
emits a `Finding` per confirmed match. Subclasses declare only what differs:
the pattern, the type label, the confidence, and — if relevant — a validation.
"""

import re
from collections.abc import Iterator
from typing import ClassVar

from maskon.models import Finding


class Detector:
    # Class-level config, set by each subclass (not per-instance state).
    type: ClassVar[str]  # PII label, e.g. "IBAN"
    confidence: ClassVar[float]  # confidence attached to every match
    _pattern: ClassVar[re.Pattern[str]]  # the shape to look for

    def _is_valid(self, candidate: str) -> bool:
        """Confirm a candidate. Default: accept (no checksum). Checksum
        detectors override this with their validator."""
        return True

    def _matches(self, text: str) -> Iterator[re.Match[str]]:
        """Candidate matches, leftmost first. Default: the pattern's finditer.
        A detector overrides this only to change *how* matches are found
        (e.g. to stay linear), never *which* ones."""
        return self._pattern.finditer(text)

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in self._matches(text):
            if self._is_valid(match.group()):
                findings.append(
                    Finding(
                        type=self.type,
                        start=match.start(),
                        end=match.end(),
                        confidence=self.confidence,
                    )
                )
        return findings
