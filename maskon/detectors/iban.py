"""IBAN detector: an International Bank Account Number.

Method = shape (regex) + proof (mod-97 checksum). The regex finds anything
shaped like an IBAN; the checksum confirms it is genuine.
"""

import re

from maskon.detectors.validators.mod97 import mod97
from maskon.models import Finding

# Two letters (country) + two check digits, then 11–30 alphanumerics,
# optionally separated into groups of 4 by single spaces.
_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b")


class IbanDetector:
    type = "IBAN"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _PATTERN.finditer(text):
            if mod97(match.group()):
                findings.append(
                    Finding(
                        type=self.type,
                        start=match.start(),
                        end=match.end(),
                        confidence=1.0,  # validated by checksum
                    )
                )
        return findings
