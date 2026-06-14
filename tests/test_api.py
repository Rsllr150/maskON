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
