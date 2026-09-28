"""Tests for the HTTP API — the thin shell. Uses FastAPI's in-memory client."""

from fastapi.testclient import TestClient

from maskon.api.app import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_detect_returns_findings():
    response = client.post("/detect", json={"text": "IBAN FR7630006000011234567890189"})
    assert response.status_code == 200
    types = [f["type"] for f in response.json()["findings"]]
    assert "IBAN" in types


def test_redact_masks_with_label():
    response = client.post("/redact", json={"text": "mail a@b.com", "mask": "label"})
    assert response.status_code == 200
    assert response.json()["redacted"] == "mail [EMAIL]"


def test_redact_defaults_to_label_mask():
    response = client.post("/redact", json={"text": "mail a@b.com"})
    assert response.json()["redacted"] == "mail [EMAIL]"


def test_invalid_mask_is_rejected():
    response = client.post("/redact", json={"text": "x", "mask": "banana"})
    assert response.status_code == 422  # Pydantic validation, no code written


def test_list_detectors():
    response = client.get("/detectors")
    types = {d["type"] for d in response.json()}
    assert {"SIREN", "IBAN", "EMAIL", "TEL"} <= types


def test_redact_stream():
    body = "mail a@b.com and IBAN FR7630006000011234567890189"
    response = client.post("/redact/stream?mask=label", content=body)
    assert response.status_code == 200
    assert "[EMAIL]" in response.text
    assert "[IBAN]" in response.text
    assert "a@b.com" not in response.text


def test_redact_stream_invalid_mask():
    response = client.post("/redact/stream?mask=banana", content="x")
    assert response.status_code == 422


def test_request_id_header_is_set():
    response = client.get("/health")
    assert "X-Request-ID" in response.headers


def test_request_id_is_echoed_when_provided():
    response = client.get("/health", headers={"X-Request-ID": "my-id-42"})
    assert response.headers["X-Request-ID"] == "my-id-42"


def test_metrics_endpoint_exposes_counters():
    client.post("/redact", json={"text": "mail a@b.com, IBAN DE89370400440532013000"})
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "maskon_requests_total" in response.text
    assert "maskon_findings_total" in response.text


def test_body_over_limit_is_rejected(monkeypatch):
    monkeypatch.setenv("MASKON_MAX_BYTES", "100")
    response = client.post("/redact", json={"text": "x" * 200})
    assert response.status_code == 413


def test_body_under_limit_is_accepted(monkeypatch):
    monkeypatch.setenv("MASKON_MAX_BYTES", "100")
    response = client.post("/redact", json={"text": "mail a@b.com"})
    assert response.status_code == 200


def test_chunked_body_over_limit_is_rejected(monkeypatch):
    # A generator body is sent chunked: no Content-Length to trust.
    monkeypatch.setenv("MASKON_MAX_BYTES", "100")
    chunks = (b"x" * 40 for _ in range(5))
    response = client.post("/redact/stream", content=chunks)
    assert response.status_code == 413


def test_chunked_json_body_over_limit_is_rejected(monkeypatch):
    monkeypatch.setenv("MASKON_MAX_BYTES", "100")
    chunks = (part for part in [b'{"text": "', b"x" * 200, b'"}'])
    response = client.post(
        "/detect", content=chunks, headers={"content-type": "application/json"}
    )
    assert response.status_code == 413


def test_default_limit_is_one_megabyte(monkeypatch):
    monkeypatch.delenv("MASKON_MAX_BYTES", raising=False)
    assert client.post("/detect", json={"text": "x" * 999_000}).status_code == 200
    assert client.post("/detect", json={"text": "x" * 1_000_001}).status_code == 413
