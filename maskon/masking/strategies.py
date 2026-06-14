"""Masking strategies.

A strategy decides what a single piece of PII becomes. It receives the original
matched text and its type, and returns the replacement string. It knows nothing
about positions or the rest of the text — that is the applier's job.
"""


def label(original: str, pii_type: str) -> str:
    """Irreversible, readable: replace the value by its type, e.g. "[IBAN]"."""
    return f"[{pii_type}]"


def partial(original: str, pii_type: str) -> str:
    """Keep the edges, mask the middle: "FR76****189". Handy for support."""
    keep_start, keep_end = 4, 3
    if len(original) <= keep_start + keep_end:
        return "*" * len(original)
    return original[:keep_start] + "****" + original[-keep_end:]


# Registry so callers (service, API) can pick a strategy by name.
STRATEGIES = {
    "label": label,
    "partial": partial,
}
