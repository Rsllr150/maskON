"""Load the annotated corpus (one JSON object per line)."""

import json
from pathlib import Path

from maskon.evaluation.models import AnnotatedExample, GoldSpan


def load_corpus(path: str | Path) -> list[AnnotatedExample]:
    examples: list[AnnotatedExample] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        obj = json.loads(line)
        spans = [
            GoldSpan(type=s["type"], start=s["start"], end=s["end"])
            for s in obj["spans"]
        ]
        examples.append(AnnotatedExample(text=obj["text"], spans=spans))
    return examples
