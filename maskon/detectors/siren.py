"""SIREN detector: a 9-digit French company identification number.

Method = shape (regex) + proof (Luhn checksum). The regex casts a wide net;
the checksum removes false positives (invoice numbers, etc.).
"""

import re

from maskon.detectors.base import Detector
from maskon.detectors.validators.luhn import luhn


class SirenDetector(Detector):
    type = "SIREN"
    confidence = 1.0  # validated by checksum
    # 9 digits, optionally grouped 3-3-3 with spaces.
    # \b at both ends avoids matching inside a longer run of digits.
    _pattern = re.compile(r"\b\d{3} ?\d{3} ?\d{3}\b")
    max_len = 11  # 9 digits + 2 spaces

    def _is_valid(self, candidate: str) -> bool:
        # Strip spaces before validating the control key.
        return luhn(candidate.replace(" ", ""))
