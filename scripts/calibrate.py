"""CLI: compare each detector's declared confidence to its measured precision.

Usage: python -m scripts.calibrate
"""

from pathlib import Path

from maskon.evaluation.calibrate import calibrate
from maskon.evaluation.corpus import load_corpus
from maskon.service.redaction import RedactionService

CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "annotated.jsonl"


def main() -> None:
    examples = load_corpus(CORPUS)
    rows = calibrate(examples, RedactionService())

    print(f"\nConfidence calibration — {len(examples)} annotated examples\n")
    print(f"{'TYPE':8}{'declared':>10}{'measured':>10}{'support':>9}{'gap':>8}")
    print("-" * 45)
    for row in rows:
        gap = row.measured - row.declared
        print(
            f"{row.pii_type:8}{row.declared:>10.2f}{row.measured:>10.2f}"
            f"{row.support:>9}{gap:>+8.2f}"
        )
    print(
        "\nNote: on a small corpus these are indicative — tune the priors by hand"
        "\nwith this evidence, don't copy them blindly (that overfits a few cases)."
    )


if __name__ == "__main__":
    main()
