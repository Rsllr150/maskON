"""IBAN detector: an International Bank Account Number.

Method = shape (regex) + proof (mod-97 checksum). The regex finds anything
shaped like an IBAN; the checksum confirms it is genuine.
"""

import re

from maskon.detectors.base import Detector
from maskon.detectors.validators.mod97 import mod97


class IbanDetector(Detector):
    type = "IBAN"
    confidence = 1.0  # validated by checksum
    # Two letters (country) + two check digits, then the rest, as EITHER:
    #   - a compact run of 11–30 alphanumerics (no spaces), or
    #   - space-separated groups of 4 with an optional short final group.
    # Splitting the two forms (rather than an optional space everywhere) stops
    # the match from greedily bridging two adjacent IBANs across a space — a bug
    # found by property-based testing.
    _pattern = re.compile(
        r"\b[A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4})+(?: [A-Z0-9]{1,3})?)\b"
    )

    def _is_valid(self, candidate: str) -> bool:
        return mod97(candidate)
