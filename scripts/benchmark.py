"""CLI: measure detection / redaction throughput on synthetic text.

Usage: python -m scripts.benchmark
"""

import time

from maskon.service.redaction import RedactionService

_SAMPLE = (
    "Client Jean Dupont, tel 06 12 34 56 78, "
    "IBAN FR76 3000 6000 0112 3456 7890 189, mail jean.dupont@example.com, "
    "SIREN 443061841, carte 4111 1111 1111 1111. Lorem ipsum dolor sit amet, "
    "rien de sensible ici, juste du texte de remplissage pour le benchmark. "
)


def _build_text(target_mb: float) -> str:
    target = int(target_mb * 1024 * 1024)
    return _SAMPLE * (target // len(_SAMPLE) + 1)


def main() -> None:
    service = RedactionService()
    text = _build_text(5.0)
    size_mb = len(text.encode("utf-8")) / 1024 / 1024

    start = time.perf_counter()
    findings = service.detect(text)
    detect_s = time.perf_counter() - start

    start = time.perf_counter()
    service.redact(text, mask="label")
    redact_s = time.perf_counter() - start

    print(f"\nMaskON benchmark — {size_mb:.1f} MB of text\n")
    print(
        f"  detect : {detect_s:6.2f} s   "
        f"{size_mb / detect_s:6.1f} MB/s   {len(findings):,} findings"
    )
    print(f"  redact : {redact_s:6.2f} s   {size_mb / redact_s:6.1f} MB/s")


if __name__ == "__main__":
    main()
