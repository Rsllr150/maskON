"""TEL detector: French phone numbers.

No checksum, so detection is shape only — but the shape is constrained enough
to be reliable: a national 0 prefix (or +33 / 0033), a first significant digit
1-9, then four pairs, with spaces / dots / dashes tolerated as separators.
Lower confidence than checksum detectors since nothing proves the number.
"""

import re

from maskon.detectors.base import Detector


class TelDetector(Detector):
    type = "TEL"
    confidence = 0.7  # shape only, no mathematical proof
    _pattern = re.compile(
        r"(?<!\d)(?:(?:\+33|0033)\s?|0)[1-9](?:[ .-]?\d{2}){4}(?!\d)"
    )
