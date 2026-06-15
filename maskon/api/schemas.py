"""HTTP contract — the Pydantic models for requests and responses.

These live at the API boundary. The internal logic keeps using the pure
`Finding` dataclass; we convert to `FindingOut` only when answering HTTP.
That keeps the core free of any web framework.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class DetectRequest(BaseModel):
    text: str


class RedactRequest(BaseModel):
    text: str
    # Only these strategies are valid; anything else → automatic 422.
    mask: Literal["label", "partial", "hash"] = "label"


class FindingOut(BaseModel):
    # from_attributes lets us build this straight from a Finding dataclass.
    model_config = ConfigDict(from_attributes=True)

    type: str
    start: int
    end: int
    confidence: float


class DetectResponse(BaseModel):
    findings: list[FindingOut]


class RedactResponse(BaseModel):
    redacted: str
    findings: list[FindingOut]


class DetectorInfo(BaseModel):
    type: str
    confidence: float
