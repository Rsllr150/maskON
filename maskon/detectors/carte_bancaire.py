"""Bank card detector (CB): a 13–19 digit payment card number.

Method = shape (regex) + proof (Luhn checksum, reused from the validators).
The same Luhn function that validates SIREN also validates card numbers — a
nice payoff of keeping validators generic.
"""

import re

from maskon.detectors.base import Detector
from maskon.detectors.validators.luhn import luhn


class CarteBancaireDetector(Detector):
    type = "CB"
    confidence = 1.0  # validated by checksum
    # 13 to 19 digits, optionally grouped with single spaces or dashes.
    _pattern = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")

    def _is_valid(self, candidate: str) -> bool:
        return luhn(candidate.replace(" ", "").replace("-", ""))
