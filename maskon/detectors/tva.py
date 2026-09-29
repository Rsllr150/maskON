"""TVA detector: a French intra-EU VAT number (FR + 2-digit key + 9-digit SIREN).

Method = shape (regex) + proof (Luhn on the embedded SIREN, plus the official
key formula: key == (12 + 3 * (SIREN % 97)) % 97). Uppercase FR only.

La Poste's SIREN (356000000) passes Luhn, so its VAT number is detected
like any other (unlike its SIRETs, see siret.py).
"""

import re

from maskon.detectors.base import Detector
from maskon.detectors.validators.luhn import luhn


class TvaDetector(Detector):
    type = "TVA"
    confidence = 1.0  # validated by checksum
    # FR + 11 digits, EITHER compact OR grouped 2-3-3-3 with single spaces —
    # never a mix. Uppercase FR only. \b at both ends avoids matching inside
    # a longer run (an IBAN, a trailing digit, a prefixed letter).
    _pattern = re.compile(r"\b(?:FR\d{11}|FR \d{2} \d{3} \d{3} \d{3})\b")
    max_len = 17  # "FR" + 11 digits + 4 spaces

    def _is_valid(self, candidate: str) -> bool:
        digits = candidate.replace("FR", "").replace(" ", "")
        if len(digits) != 11 or not digits.isdigit():
            return False
        key, siren = digits[:2], digits[2:]
        return luhn(siren) and int(key) == (12 + 3 * (int(siren) % 97)) % 97
