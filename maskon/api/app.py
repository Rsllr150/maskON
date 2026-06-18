"""FastAPI application — the thin HTTP shell over the service.

No business logic here: each route validates input (via Pydantic), calls the
service, converts findings to the HTTP schema, and returns. The intelligence
lives in maskon/service and maskon/detectors. Requests are instrumented for
Prometheus (see maskon/api/metrics and the /metrics endpoint).
"""

from collections.abc import Iterator
from typing import Literal

from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from maskon.api.metrics import BYTES, FINDINGS, LATENCY, REQUESTS
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


def _count_findings(findings: list[Finding]) -> None:
    for finding in findings:
        FINDINGS.labels(finding.type).inc()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/detect", response_model=DetectResponse)
def detect(request: DetectRequest) -> DetectResponse:
    with LATENCY.labels("/detect").time():
        REQUESTS.labels("/detect").inc()
        BYTES.inc(len(request.text))
        findings = service.detect(request.text)
        _count_findings(findings)
        return DetectResponse(findings=_to_out(findings))


@app.post("/redact", response_model=RedactResponse)
def redact(request: RedactRequest) -> RedactResponse:
    with LATENCY.labels("/redact").time():
        REQUESTS.labels("/redact").inc()
        BYTES.inc(len(request.text))
        redacted, findings = service.redact(request.text, mask=request.mask)
        _count_findings(findings)
        return RedactResponse(redacted=redacted, findings=_to_out(findings))


@app.get("/detectors", response_model=list[DetectorInfo])
def detectors() -> list[DetectorInfo]:
    return [
        DetectorInfo(type=d.type, confidence=d.confidence) for d in service.detectors
    ]


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


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
    REQUESTS.labels("/redact/stream").inc()
    BYTES.inc(len(text))

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
