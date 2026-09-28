"""The orchestration service — the entry point for all business logic.

It owns the list of detectors, normalises the text, runs every detector on
that cleaned form, merges the results, and remaps each span onto the original
(so masking still rewrites the caller's string). Strategies see the
normalised value. No HTTP here: the API simply calls this.
"""

from maskon.detectors.base import Detector
from maskon.detectors.carte_bancaire import CarteBancaireDetector
from maskon.detectors.email import EmailDetector
from maskon.detectors.iban import IbanDetector
from maskon.detectors.nir import NirDetector
from maskon.detectors.passeport import PasseportDetector
from maskon.detectors.siren import SirenDetector
from maskon.detectors.siret import SiretDetector
from maskon.detectors.siv import SivDetector
from maskon.detectors.spi import SpiDetector
from maskon.detectors.tel import TelDetector
from maskon.detectors.tva import TvaDetector
from maskon.masking.apply import Strategy, apply_mask
from maskon.masking.strategies import (
    MissingHashKey,
    build_strategies,
    default_hash_key,
    default_hash_key_version,
)
from maskon.models import Finding
from maskon.normalize import normalize
from maskon.service.merge import merge_overlapping


def _default_detectors() -> list[Detector]:
    return [
        SirenDetector(),
        SiretDetector(),
        IbanDetector(),
        NirDetector(),
        CarteBancaireDetector(),
        EmailDetector(),
        TelDetector(),
        SpiDetector(),
        PasseportDetector(),
        SivDetector(),
        TvaDetector(),
    ]


class RedactionService:
    def __init__(
        self,
        detectors: list[Detector] | None = None,
        hash_key: bytes | None = None,
        hash_key_version: str | None = None,
    ):
        # Detectors and the HMAC hash key (and its version) can be injected
        # (handy for tests and for not baking config in at import time);
        # otherwise use the defaults. A too-short key raises WeakHashKey here.
        self.detectors = detectors if detectors is not None else _default_detectors()
        key = hash_key if hash_key is not None else default_hash_key()
        version = (
            hash_key_version
            if hash_key_version is not None
            else default_hash_key_version()
        )
        self._strategies = build_strategies(key, version)

    def strategy_for(self, mask: str) -> Strategy:
        # Validate here so the core is self-sufficient, independent of any
        # caller (a script using the service directly must get a clear error,
        # not a raw KeyError).
        if mask == "hash" and mask not in self._strategies:
            raise MissingHashKey(
                "mask='hash' needs a key: pass hash_key=... or set MASKON_HASH_KEY"
            )
        if mask not in self._strategies:
            raise ValueError(
                f"unknown mask {mask!r}, expected one of {sorted(self._strategies)}"
            )
        strategy = self._partial if mask == "partial" else self._strategies[mask]
        return lambda value, pii_type: strategy(normalize(value)[0], pii_type)

    def _partial(self, original: str, pii_type: str) -> str:
        # A merged span is the union of overlapping findings but carries only
        # the winner's label, so it may hold another PII's characters (a TEL
        # inside an EMAIL, a NIR that is also a CB). The per-type rule shows
        # edges; it applies only when the value is exactly ONE raw detection,
        # of that type, over all detectors — otherwise nothing is shown.
        raw = [
            (d.type, f.start, f.end) for d in self.detectors for f in d.detect(original)
        ]
        exact = raw == [(pii_type, 0, len(original))]
        return self._strategies["partial"](original, pii_type) if exact else "****"

    def detect(self, text: str) -> list[Finding]:
        normalized, offsets = normalize(text)
        findings: list[Finding] = []
        for detector in self.detectors:
            findings += detector.detect(normalized)
        remapped = [
            Finding(
                type=f.type,
                start=offsets[f.start],
                end=offsets[f.end - 1] + 1,
                confidence=f.confidence,
            )
            for f in merge_overlapping(findings)
            if f.start < f.end
        ]
        return remapped

    def redact(self, text: str, mask: str = "label") -> tuple[str, list[Finding]]:
        strategy = self.strategy_for(mask)
        findings = self.detect(text)
        redacted = apply_mask(text, findings, strategy)
        return redacted, findings
