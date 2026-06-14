"""The orchestration service — the entry point for all business logic.

It owns the list of detectors, runs every one of them on the text, and merges
the results into a clean, non-overlapping list of findings. No HTTP here: the
API will simply call this. Masking will be wired in later (redact()).
"""

from maskon.detectors.base import Detector
from maskon.detectors.carte_bancaire import CarteBancaireDetector
from maskon.detectors.email import EmailDetector
from maskon.detectors.iban import IbanDetector
from maskon.detectors.nir import NirDetector
from maskon.detectors.siren import SirenDetector
from maskon.detectors.tel import TelDetector
from maskon.masking.apply import apply_mask
from maskon.masking.strategies import STRATEGIES
from maskon.models import Finding
from maskon.service.merge import merge_overlapping


def _default_detectors() -> list[Detector]:
    return [
        SirenDetector(),
        IbanDetector(),
        NirDetector(),
        CarteBancaireDetector(),
        EmailDetector(),
        TelDetector(),
    ]


class RedactionService:
    def __init__(self, detectors: list[Detector] | None = None):
        # Detectors can be injected (handy for tests); otherwise use them all.
        self.detectors = detectors if detectors is not None else _default_detectors()

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self.detectors:
            findings += detector.detect(text)
        return merge_overlapping(findings)

    def redact(self, text: str, mask: str = "label") -> tuple[str, list[Finding]]:
        # Validate here so the core is self-sufficient, independent of any
        # caller (the API also validates, but a script using the service
        # directly must get a clear error, not a raw KeyError).
        if mask not in STRATEGIES:
            raise ValueError(
                f"unknown mask {mask!r}, expected one of {sorted(STRATEGIES)}"
            )
        # Detect first, then rewrite the text with the chosen strategy.
        findings = self.detect(text)
        redacted = apply_mask(text, findings, STRATEGIES[mask])
        return redacted, findings
