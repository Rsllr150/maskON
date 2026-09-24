"""French passport number detector.

Method = shape only (no public checksum).
"""

import re

from maskon.detectors.base import Detector


class PasseportDetector(Detector):
    type = "PASSEPORT"
    confidence = 0.8  # shape only, no proof
    # 2 digits, 2 uppercase letters, 5 digits. No inner spaces.
    # \b at both ends avoids matching inside a longer token.
    _pattern = re.compile(r"\b\d{2}[A-Z]{2}\d{5}\b")
