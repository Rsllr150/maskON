"""EMAIL detector.

No checksum exists for an email address, so detection is pure shape (regex).
The pattern is the pragmatic, widely-used one — not the full RFC 5322 grammar,
which is impractical and matches almost nothing extra in real text.
"""

import re

from maskon.detectors.base import Detector


class EmailDetector(Detector):
    type = "EMAIL"
    confidence = 0.9  # no checksum, but the shape is highly distinctive
    _pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
