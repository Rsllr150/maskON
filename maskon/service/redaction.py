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
from maskon.masking.apply import Strategy, apply_mask
from maskon.masking.strategies import build_strategies, default_hash_key
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
    def __init__(
        self,
        detectors: list[Detector] | None = None,
        hash_key: bytes | None = None,
    ):
        # Detectors and the HMAC hash key can be injected (handy for tests and
        # for not baking config in at import time); otherwise use the defaults.
        self.detectors = detectors if detectors is not None else _default_detectors()
        key = hash_key if hash_key is not None else default_hash_key()
        self._strategies = build_strategies(key)

    def strategy_for(self, mask: str) -> Strategy:
        # Validate here so the core is self-sufficient, independent of any
        # caller (a script using the service directly must get a clear error,
        # not a raw KeyError).
        if mask not in self._strategies:
            raise ValueError(
                f"unknown mask {mask!r}, expected one of {sorted(self._strategies)}"
            )
        return self._strategies[mask]

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self.detectors:
            findings += detector.detect(text)
        return merge_overlapping(findings)

    def redact(self, text: str, mask: str = "label") -> tuple[str, list[Finding]]:
        strategy = self.strategy_for(mask)
        findings = self.detect(text)
        redacted = apply_mask(text, findings, strategy)
        return redacted, findings
