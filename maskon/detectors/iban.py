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
    # Two letters (country) + two check digits, then 11–30 alphanumerics,
    # optionally separated into groups of 4 by single spaces.
    _pattern = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b")

    def _is_valid(self, candidate: str) -> bool:
        return mod97(candidate)
