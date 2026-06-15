# MaskON

[![CI](https://github.com/Rsllr150/maskON/actions/workflows/ci.yml/badge.svg)](https://github.com/Rsllr150/maskON/actions/workflows/ci.yml)

Microservice for **detecting and masking personally identifiable information (PII)**,
specialized in French formats (IBAN, SIREN, NIR, phone numbers…).

You send it text, it returns the same text with the PII masked plus a report of what it
found — to scrub your logs, your LLM prompts or your datasets before they leak in clear.

Serious detection rather than two homemade regexes: each type is validated by a checksum
(Luhn, mod 97, control key) to drive down false positives.

> 🚧 Work in progress.

## Detection quality

Measured on a hand-annotated corpus (`corpus/annotated.jsonl`), with **exact span
matching** — a finding counts only if its `(type, start, end)` matches the annotation
exactly. Reproduce with `python -m scripts.evaluate`.

| Type        | Precision | Recall | F1   |
| ----------- | --------- | ------ | ---- |
| CB          | 100%      | 100%   | 1.00 |
| EMAIL       | 100%      | 100%   | 1.00 |
| IBAN        | 100%      | 75%    | 0.86 |
| NIR         | 100%      | 100%   | 1.00 |
| SIREN       | 100%      | 100%   | 1.00 |
| TEL         | 80%       | 80%    | 0.80 |
| **Overall** | **94%**   | **89%**| **0.92** |

The checksum detectors (SIREN, IBAN, NIR, CB) are near-perfect on precision. The gaps are
honest and known:

- **IBAN recall** — a lowercase IBAN is missed (the regex expects uppercase).
- **TEL** — one false positive (`0123456789`, an order number read as a phone) and one
  miss (`+33 (0)6 …`, parentheses break the pattern).

These are exactly the cases the corpus is meant to surface and track over time.

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

| Endpoint             | Role                                              |
| -------------------- | ------------------------------------------------- |
| `POST /detect`       | Locate PII without masking (audit / dry-run)      |
| `POST /redact`       | Locate **and** mask (`mask`: `label` / `partial`) |
| `POST /redact/stream`| Stream large input, redacted with bounded memory  |
| `GET  /detectors`    | List active detectors and their confidence        |
| `GET  /health`       | Liveness check                                     |

### Streaming

`/redact/stream` processes the text chunk by chunk so a multi-gigabyte log file
never has to fit in memory. A PII can straddle a chunk boundary (an IBAN cut in
half); a sliding **overlap buffer** of a few dozen characters carries the tail of
each chunk forward so a split PII is still caught — proven by
`tests/test_streaming.py::test_pii_split_across_two_chunks_is_still_redacted`.
