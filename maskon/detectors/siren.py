"""SIREN detector: a 9-digit French company identification number.

Method = shape (regex) + proof (Luhn checksum). The regex casts a wide net;
the checksum removes false positives (invoice numbers, etc.).
"""

import re

from maskon.detectors.validators.luhn import luhn
from maskon.models import Finding

# 9 digits, optionally grouped 3-3-3 with spaces.
# \b at both ends avoids matching inside a longer run of digits.
_PATTERN = re.compile(r"\b\d{3} ?\d{3} ?\d{3}\b")


class SirenDetector:
    type = "SIREN"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _PATTERN.finditer(text):
            candidate = match.group()
            # Strip spaces before validating the control key.
            digits = candidate.replace(" ", "")
            if luhn(digits):
                findings.append(
                    Finding(
                        type=self.type,
                        start=match.start(),
                        end=match.end(),
                        confidence=1.0,  # validated by checksum
                    )
                )
        return findings
