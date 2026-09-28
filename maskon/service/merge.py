"""Resolve overlapping findings into a clean, non-overlapping list.

Pure function. Fail-closed: findings that overlap (directly or through a chain)
become ONE finding covering the union of their spans, so no character a
detector saw is left in clear. The priority rule only picks the label: higher
confidence wins; on a tie, the longer span wins; on an exact tie, the more
specific type wins (a 14-digit number valid as both SIRET and CB is a SIRET, a
13-digit one valid as both SPI and CB is a SPI, a 15-digit one valid as both
NIR and CB is a NIR). Disjoint findings are all
kept, ordered by position.
"""

from maskon.models import Finding

# Tie-break for identical (confidence, length): higher = more specific.
# Makes SIRET-vs-CB, SPI-vs-CB and NIR-vs-CB independent of the order detectors
# are registered in.
_SPECIFICITY = {"SIRET": 1, "SPI": 1, "NIR": 1}


def _priority(f: Finding) -> tuple[float, int, int]:
    # What makes a finding "better": more confidence, then more length, then
    # a more specific type.
    return (f.confidence, f.end - f.start, _SPECIFICITY.get(f.type, 0))


def _union(cluster: list[Finding]) -> Finding:
    # The span covers every member; the label comes from the best one.
    best = max(cluster, key=_priority)
    start = min(f.start for f in cluster)
    end = max(f.end for f in cluster)
    return Finding(best.type, start, end, best.confidence)


def merge_overlapping(findings: list[Finding]) -> list[Finding]:
    # Left to right: a finding that starts before the cluster's end joins it.
    ordered = sorted(findings, key=lambda f: f.start)

    clusters: list[list[Finding]] = []
    end = 0
    for f in ordered:
        if clusters and f.start < end:
            clusters[-1].append(f)
            end = max(end, f.end)
        else:
            clusters.append([f])
            end = f.end
    return [_union(c) for c in clusters]
