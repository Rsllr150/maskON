# MaskON

[![CI](https://github.com/Rsllr150/maskON/actions/workflows/ci.yml/badge.svg)](https://github.com/Rsllr150/maskON/actions/workflows/ci.yml)

Microservice for **detecting and masking personally identifiable information (PII)**,
specialized in French formats (IBAN, SIREN, NIR, phone numbers…).

You send it text, it returns the same text with the PII masked plus a report of what it
found — to scrub your logs, your LLM prompts or your datasets before they leak in clear.

Serious detection rather than two homemade regexes: each type is validated by a checksum
(Luhn, mod 97, control key) to drive down false positives.

> 🚧 Work in progress.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn maskon.api.app:app --reload
```

Interactive docs are then served at http://127.0.0.1:8000/docs.

## Example

```bash
curl -X POST http://127.0.0.1:8000/redact \
  -H "Content-Type: application/json" \
  -d '{"text": "Jean au 06 12 34 56 78, IBAN FR76 3000 6000 0112 3456 7890 189", "mask": "label"}'
```

```json
{
  "redacted": "Jean au [TEL], IBAN [IBAN]",
  "findings": [
    { "type": "TEL",  "start": 8,  "end": 22, "confidence": 0.7 },
    { "type": "IBAN", "start": 29, "end": 62, "confidence": 1.0 }
  ]
}
```

## Endpoints

| Endpoint          | Role                                          |
| ----------------- | --------------------------------------------- |
| `POST /detect`    | Locate PII without masking (audit / dry-run)  |
| `POST /redact`    | Locate **and** mask (`mask`: `label` / `partial`) |
| `GET  /detectors` | List active detectors and their confidence    |
| `GET  /health`    | Liveness check                                |
