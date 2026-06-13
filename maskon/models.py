"""Internal data objects, shared across all layers.

`Finding` is the PIVOT object of the project: a detector PRODUCES them, the
service MERGES them, masking USES them to replace text. It is a plain dataclass
— no dependency on HTTP or any framework.
"""

from dataclasses import dataclass


@dataclass
class Finding:
    type: str  # kind of PII, e.g. "SIREN", "IBAN", "EMAIL"
    start: int  # index of the first character in the source text
    end: int  # end index (exclusive), Python-slice style: text[start:end]
    confidence: float  # 0.0 to 1.0 ; 1.0 = validated by checksum
