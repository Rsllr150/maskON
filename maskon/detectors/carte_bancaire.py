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
    # 13 to 19 digits, as EITHER a compact run, OR groups of 4 separated by a
    # single space/dash with an optional short final group. Capping the grouped
    # form (rather than an optional separator everywhere) stops the match from
    # bridging two adjacent card numbers — a bug found by property-based testing.
    _pattern = re.compile(r"\b(?:\d{13,19}|\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?)\b")

    def _is_valid(self, candidate: str) -> bool:
        return luhn(candidate.replace(" ", "").replace("-", ""))
