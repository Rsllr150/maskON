"""Base class shared by every detector.

A detector scans text with a regex, optionally validates each candidate, and
emits a `Finding` per confirmed match. Subclasses declare only what differs:
the pattern, the type label, the confidence, and — if relevant — a validation.
"""

import re

from maskon.models import Finding


class Detector:
    type: str  # PII label, e.g. "IBAN"
    confidence: float  # confidence attached to every match of this detector
    _pattern: re.Pattern[str]  # the shape to look for

    def _is_valid(self, candidate: str) -> bool:
        """Confirm a candidate. Default: accept (no checksum). Checksum
        detectors override this with their validator."""
        return True

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in self._pattern.finditer(text):
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
