"""SIRET detector: a 14-digit French establishment number (SIREN + 5-digit NIC).

Method = shape (regex) + proof (Luhn checksum). A real SIRET embeds a real
SIREN, so both keys must pass: the 14 digits AND the first 9. La Poste is the
one documented exception — its establishments share SIREN 356000000 and are
validated by "sum of the digits is a multiple of 5" instead.
"""

import re

from maskon.detectors.base import Detector
from maskon.detectors.validators.luhn import luhn

_LA_POSTE_SIREN = "356000000"


class SiretDetector(Detector):
    type = "SIRET"
    confidence = 1.0  # validated by checksum
    # 14 digits, EITHER compact OR grouped 3-3-3-5 with single spaces — never a
    # mix, so "SIREN 443061841 10004 euros" can't swallow the amount.
    # \b at both ends avoids matching inside a longer run of digits.
    _pattern = re.compile(r"\b(?:\d{14}|\d{3} \d{3} \d{3} \d{5})\b")

    def _is_valid(self, candidate: str) -> bool:
        digits = candidate.replace(" ", "")
        if digits.startswith(_LA_POSTE_SIREN):
            return sum(int(d) for d in digits) % 5 == 0
        return luhn(digits) and luhn(digits[:9])
