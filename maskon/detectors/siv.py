"""SIV detector: a French licence plate in the current SIV format (AB-123-CD).

Method = shape only. There is no checksum on SIV plates. The old FNI format
(123 AB 45) is out of scope.
"""

import re

from maskon.detectors.base import Detector


class SivDetector(Detector):
    type = "IMMAT"
    confidence = 0.8  # shape only — no checksum exists for SIV plates
    # 2 letters, 3 digits, 2 letters. Letters exclude I, O, U.
    # Same separator (- or a single space) on both sides; no compact form.
    # \b at both ends avoids matching inside a longer token.
    _pattern = re.compile(r"\b[A-HJ-NP-TV-Z]{2}([- ])(?!000)\d{3}\1[A-HJ-NP-TV-Z]{2}\b")
