"""Performance guard: no detector may be super-linear on a hostile input.

A quadratic regex lets one request block a worker (the EMAIL pattern once
took ~45 min on 1 MB). For every detector and every trap — a unit repeated
to build long runs of the characters its pattern consumes — doubling the
input must not much more than double the time.
"""

import time

import pytest

from maskon.detectors.base import Detector
from maskon.service.redaction import RedactionService

service = RedactionService()

TRAPS = ["a", "a.", "a-", "a@", "@a.", "a@a", "1", "1 ", "0", "A", "AB-", "+33 "]
# An unbounded IBAN shape feeds `int()` more than 4300 digits and raises.
# Not a regex-complexity bug: tracked separately, pinned here so it can't hide.
IBAN_TRAPS = ["AA11 ", "FR76 "]

N = 200_000


def _best_time(detector: Detector, text: str) -> float:
    best = float("inf")
    for _ in range(5):
        start = time.perf_counter()
        detector.detect(text)
        best = min(best, time.perf_counter() - start)
    return best


def _cases() -> list[object]:
    cases: list[object] = []
    for detector in service.detectors:
        for trap in TRAPS + IBAN_TRAPS:
            marks = []
            if detector.type == "IBAN" and trap in IBAN_TRAPS:
                marks = [pytest.mark.xfail(raises=ValueError, strict=True)]
            cases.append(
                pytest.param(
                    detector, trap, marks=marks, id=f"{detector.type}-{trap!r}"
                )
            )
    return cases


@pytest.mark.parametrize(("detector", "trap"), _cases())
def test_detector_is_linear(detector: Detector, trap: str):
    text = trap * (N // len(trap))
    small = _best_time(detector, text)
    large = _best_time(detector, text + text)
    # Linear → ~2; quadratic → ~4. Linear detectors take ~1 ms here, so a 5 ms
    # floor keeps timer noise out; a quadratic one takes seconds, far above it.
    assert large / max(small, 5e-3) < 3


@pytest.mark.parametrize("trap", TRAPS)
def test_one_megabyte_trap_is_fast(trap: str):
    text = trap * (1_000_000 // len(trap))
    start = time.perf_counter()
    service.detect(text)
    assert time.perf_counter() - start < 1.0
