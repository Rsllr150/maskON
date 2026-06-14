"""NIR detector: a French social security number (15 characters).

Method = shape (regex) + proof (control-key checksum). Handles the spaced,
compact and Corsican (2A/2B) forms.
"""

import re

from maskon.detectors.base import Detector
from maskon.detectors.validators.cle_nir import cle_nir


class NirDetector(Detector):
    type = "NIR"
    confidence = 1.0  # validated by checksum
    # sex(1) year(2) month(2) dept(2 or 2A/2B) commune(3) order(3) key(2),
    # optionally separated by single spaces.
    _pattern = re.compile(
        r"\b[12] ?\d{2} ?\d{2} ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b"
    )

    def _is_valid(self, candidate: str) -> bool:
        return cle_nir(candidate)
