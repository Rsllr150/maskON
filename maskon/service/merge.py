"""Resolve overlapping findings into a clean, non-overlapping list.

Pure function. Two findings that cover the same characters cannot both be
masked, so we keep the better one. Rule: higher confidence wins; on a tie, the
longer span wins. Disjoint findings are all kept, ordered by position.
"""

from maskon.models import Finding


def _priority(f: Finding) -> tuple[float, int]:
    # What makes a finding "better": more confidence, then more length.
    return (f.confidence, f.end - f.start)


def merge_overlapping(findings: list[Finding]) -> list[Finding]:
    # Process left to right; at equal start, the stronger one comes first.
    ordered = sorted(findings, key=lambda f: (f.start, -f.confidence))

    kept: list[Finding] = []
    for f in ordered:
        # Overlap = this finding starts before the last kept one ends.
        if kept and f.start < kept[-1].end:
            # Replace the previous one only if this one is strictly better.
            if _priority(f) > _priority(kept[-1]):
                kept[-1] = f
            # otherwise drop f
        else:
            kept.append(f)
    return kept
