"""FastAPI application — the thin HTTP shell over the service.

No business logic here: each route validates input (via Pydantic), calls the
service, converts findings to the HTTP schema, and returns. The intelligence
lives in maskon/service and maskon/detectors.
"""

from collections.abc import Iterator
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse

from maskon.api.schemas import (
    DetectorInfo,
    DetectRequest,
    DetectResponse,
    FindingOut,
    RedactRequest,
    RedactResponse,
)
from maskon.models import Finding
from maskon.service.redaction import RedactionService
from maskon.streaming.stream import StreamRedactor

app = FastAPI(
    title="MaskON",
    description="Detect and mask personally identifiable information (PII).",
    version="0.1.0",
)

# Stateless service → one shared instance is safe.
service = RedactionService()


def _to_out(findings: list[Finding]) -> list[FindingOut]:
    return [FindingOut.model_validate(f) for f in findings]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/detect", response_model=DetectResponse)
def detect(request: DetectRequest) -> DetectResponse:
    findings = service.detect(request.text)
    return DetectResponse(findings=_to_out(findings))


@app.post("/redact", response_model=RedactResponse)
def redact(request: RedactRequest) -> RedactResponse:
    redacted, findings = service.redact(request.text, mask=request.mask)
    return RedactResponse(redacted=redacted, findings=_to_out(findings))


@app.get("/detectors", response_model=list[DetectorInfo])
def detectors() -> list[DetectorInfo]:
    return [
        DetectorInfo(type=d.type, confidence=d.confidence) for d in service.detectors
    ]


_STREAM_CHUNK = 4096


@app.post("/redact/stream")
async def redact_stream(
    request: Request, mask: Literal["label", "partial", "hash"] = "label"
) -> StreamingResponse:
    # We read the request body fully here (true request-side streaming + a
    # streaming response deadlocks under the half-duplex test client), then
    # stream the *response*: the StreamRedactor is fed chunk by chunk and we
    # yield redacted output as it becomes ready. The memory-bounded streaming
    # logic lives in maskon.streaming; for unbounded inputs use it directly.
    text = (await request.body()).decode("utf-8")

    def generate() -> Iterator[bytes]:
        redactor = StreamRedactor(mask=mask)
        for i in range(0, len(text), _STREAM_CHUNK):
            emitted = redactor.feed(text[i : i + _STREAM_CHUNK])
            if emitted:
                yield emitted.encode("utf-8")
        tail = redactor.flush()
        if tail:
            yield tail.encode("utf-8")

    return StreamingResponse(generate(), media_type="text/plain")
