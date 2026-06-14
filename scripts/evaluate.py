"""CLI: evaluate MaskON against the annotated corpus and print metrics.

Usage: python scripts/evaluate.py
"""

from pathlib import Path

from maskon.evaluation.corpus import load_corpus
from maskon.evaluation.evaluate import EvaluationResult, evaluate
from maskon.evaluation.metrics import Score
from maskon.service.redaction import RedactionService

CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "annotated.jsonl"


def _row(label: str, s: Score) -> str:
    return (
        f"{label:8}{s.precision:>8.0%}{s.recall:>8.0%}"
        f"{s.f1:>6.2f}{s.tp:>5}{s.fp:>5}{s.fn:>5}"
    )


def _print_report(result: EvaluationResult, n_examples: int) -> None:
    print(f"\nMaskON evaluation — {n_examples} annotated examples\n")
    print(f"{'TYPE':8}{'prec':>8}{'recall':>8}{'f1':>6}{'tp':>5}{'fp':>5}{'fn':>5}")
    print("-" * 44)
    for pii_type in sorted(result.per_type):
        print(_row(pii_type, result.per_type[pii_type]))
    print("-" * 44)
    print(_row("OVERALL", result.overall))

    if result.false_positives:
        print("\nFalse positives (flagged but not real PII):")
        for fp in result.false_positives:
            print(f"  [{fp.type}] {fp.excerpt!r}")


def main() -> None:
    examples = load_corpus(CORPUS)
    result = evaluate(examples, RedactionService())
    _print_report(result, len(examples))


if __name__ == "__main__":
    main()
