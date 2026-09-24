"""SPI detector: a 13-digit French fiscal identification number (numéro fiscal).

Method = shape (regex) + proof (SPI control key). The first 10 digits modulo
511 must equal the last 3 digits.
"""

import re

from maskon.detectors.base import Detector
from maskon.detectors.validators.cle_spi import cle_spi


class SpiDetector(Detector):
    type = "SPI"
    confidence = 1.0  # validated by checksum
    # 13 digits, EITHER compact OR grouped 2-2-3-3-3 with single spaces — never
    # a mix, so a compact prefix plus leftover digits can't swallow an amount.
    # \b at both ends avoids matching inside a longer run of digits.
    _pattern = re.compile(r"\b(?:\d{13}|\d{2} \d{2} \d{3} \d{3} \d{3})\b")

    def _is_valid(self, candidate: str) -> bool:
        return cle_spi(candidate.replace(" ", ""))
