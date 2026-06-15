"""Tests for the evaluation pipeline — corpus loading and scoring."""

from pathlib import Path

from maskon.evaluation.corpus import load_corpus
from maskon.evaluation.evaluate import evaluate
from maskon.evaluation.models import AnnotatedExample, GoldSpan
from maskon.service.redaction import RedactionService


def test_load_corpus_parses_and_skips_blank_lines(tmp_path: Path):
    path = tmp_path / "corpus.jsonl"
    path.write_text(
        '{"text": "a@b.com", "spans": [{"type": "EMAIL", "start": 0, "end": 7}]}\n'
        "\n"  # blank line must be skipped
        '{"text": "nothing", "spans": []}\n',
        encoding="utf-8",
    )
    examples = load_corpus(path)
    assert len(examples) == 2
    assert examples[0].text == "a@b.com"
    assert examples[0].spans == [GoldSpan("EMAIL", 0, 7)]
    assert examples[1].spans == []


def test_evaluate_counts_true_and_false_positives():
    examples = [
        AnnotatedExample("mail a@b.com", [GoldSpan("EMAIL", 5, 12)]),
        AnnotatedExample("ref 0123456789 here", []),  # phone-shaped, not a phone
    ]
    result = evaluate(examples, RedactionService())

    assert result.per_type["EMAIL"].tp == 1  # the email is found
    assert result.overall.tp == 1
    # The order number is flagged as TEL → a false positive we surface openly.
    assert any(fp.type == "TEL" for fp in result.false_positives)
