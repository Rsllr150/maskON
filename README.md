# MaskON

[![CI](https://github.com/Rsllr150/maskON/actions/workflows/ci.yml/badge.svg)](https://github.com/Rsllr150/maskON/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![Ruff](https://img.shields.io/badge/lint-ruff-261230)
![mypy](https://img.shields.io/badge/types-mypy%20strict-2A6DB2)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue)

**Detect and mask personally identifiable information (PII), specialized in French formats.**

You send MaskON text, it returns the same text with the PII masked plus a report of what
it found — to scrub your **logs**, your **LLM prompts** or your **shared datasets** before
they leak in clear. Serious detection rather than two homemade regexes: every structured
type is confirmed by a **checksum** (Luhn, mod 97, control key), which is what drives the
false-positive rate down.

```text
"Contact Jean au 06 12 34 56 78, IBAN FR76 3000 6000 0112 3456 7890 189"
        │
        ▼  POST /redact
"Contact Jean au [TEL], IBAN [IBAN]"
```

## Features

- **6 detectors** — IBAN, SIREN/SIRET, NIR, bank card (CB), email, French phone.
- **Checksum-validated** — shape (regex) *and* proof (Luhn / mod 97 / NIR key), so an
  invoice number that merely *looks* like a SIREN is rejected.
- **Three masking strategies** — `label`, `partial`, and keyed `hash`.
- **Streaming** — redact a 2 GB log file with bounded memory; a PII split across two
  chunks is still caught via a sliding overlap buffer.
- **Measured quality** — precision/recall on a hand-annotated corpus, not promises.
- **Pure, testable core** — the detection logic has zero dependency on HTTP.

## Quick start

```bash
# With Docker
docker build -t maskon .
docker run -p 8000:8000 maskon

# Or locally
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn maskon.api.app:app --reload
```

Interactive Swagger docs are served at <http://127.0.0.1:8000/docs>.

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

| Endpoint              | Role                                               |
| --------------------- | -------------------------------------------------- |
| `POST /detect`        | Locate PII without masking (audit / dry-run)       |
| `POST /redact`        | Locate **and** mask (`mask`: `label`/`partial`/`hash`) |
| `POST /redact/stream` | Stream large input, redacted with bounded memory   |
| `GET  /detectors`     | List active detectors and their confidence         |
| `GET  /metrics`       | Prometheus metrics (requests, findings, latency)   |
| `GET  /health`        | Liveness check                                      |

### Streaming

The streaming core (`maskon.streaming`) redacts input **chunk by chunk with bounded
memory** — a huge log file read line by line never has to fit in RAM. A PII can straddle a
chunk boundary (an IBAN cut in half); a sliding **overlap buffer** carries each chunk's tail
forward so the split PII is still caught — proven by
`tests/test_streaming.py::test_pii_split_across_two_chunks_is_still_redacted`.

`POST /redact/stream` exposes this over HTTP and streams the redacted **response**. (It reads
the request body before processing: true request-side streaming can't be exercised by the
test client, so the endpoint stays fully tested. For unbounded inputs, use the
`redact_stream()` core directly over a file iterator.)

## Masking strategies

| `mask`    | Example output  | Use case                                                  |
| --------- | --------------- | --------------------------------------------------------- |
| `label`   | `[IBAN]`        | Irreversible, readable                                    |
| `partial` | `FR76****189`   | Keep the edges, for customer support                      |
| `hash`    | `iban_3f2a9c1b` | Deterministic (same value → same token): correlate masked data without revealing it |

`hash` is keyed with **HMAC-SHA256**. Set `MASKON_HASH_KEY` in production; the built-in
default is for local use only.

## Detection quality

Measured on a **hand-built, synthetic** corpus of 74 annotated examples
(`corpus/annotated.jsonl`) with **exact span matching** — a finding counts only if its
`(type, start, end)` matches the annotation exactly. It deliberately includes hard cases
(lowercase IBANs, parenthesized phones, order numbers shaped like phones) so the numbers
stay honest. Reproduce with `python -m scripts.evaluate`.

| Type        | Precision | Recall  | F1       |
| ----------- | --------- | ------- | -------- |
| CB          | 100%      | 100%    | 1.00     |
| EMAIL       | 100%      | 100%    | 1.00     |
| IBAN        | 100%      | 81%     | 0.90     |
| NIR         | 100%      | 100%    | 1.00     |
| SIREN       | 100%      | 100%    | 1.00     |
| TEL         | 83%       | 77%     | 0.80     |
| **Overall** | **97%**   | **90%** | **0.93** |

The gaps are honest and known: the checksum types are near-perfect, while the shape-only
detectors carry the residual errors — IBAN misses lowercase / irregularly-grouped numbers,
and TEL both misses parenthesized/odd international formats and flags order numbers that look
like phones. These are exactly the cases the corpus surfaces and tracks.

Each detector ships a hand-set confidence (a prior). `python -m scripts.calibrate`
compares it to the precision actually measured on the corpus, so the priors can be
tuned with evidence rather than guessed — without overfitting a small corpus.

## Performance

`python -m scripts.benchmark` measures throughput on synthetic text. On a laptop MaskON
detects and redacts at **~10 MB/s**. Redaction assembles the output in a single O(n) pass
— an earlier O(n²) version (rebuilding the whole string per finding) was ~130× slower,
caught by this benchmark.

## How it works

Strict layering — the testable logic never depends on HTTP.

```text
api/         → HTTP shell (FastAPI), no logic
service/     → orchestrate detectors, merge overlapping spans, apply masking
detectors/   → one file per type (iban.py, nir.py …), pure logic
  validators/→ checksums (luhn, mod97, cle_nir) — pure functions, heavily tested
masking/     → label / partial / hash
streaming/   → chunking + sliding overlap buffer
evaluation/  → corpus + precision/recall metrics
```

A detector is `shape (regex) + proof (checksum)`. Each finding carries a confidence
(`1.0` for a checksum match, lower for shape-only), and the service merges overlapping
findings, keeping the most confident.

## Tech stack

| Area        | Tooling                                              |
| ----------- | --------------------------------------------------- |
| Language    | Python 3.12                                          |
| API         | FastAPI · Uvicorn · Pydantic                         |
| Core engine | Standard library only (`re`, `hmac`, `dataclasses`) |
| Tests       | pytest · Hypothesis (property-based)                 |
| Quality     | Ruff (lint + format) · mypy `--strict`              |
| Packaging   | Docker (slim, non-root, healthcheck)                |
| CI          | GitHub Actions (lint → format → types → tests)      |

## Development

```bash
pip install -r requirements-dev.txt
ruff check maskon tests scripts      # lint
ruff format maskon tests scripts     # format
mypy maskon tests scripts            # strict type check
pytest                               # tests
```

All four run on every push and pull request via GitHub Actions.
