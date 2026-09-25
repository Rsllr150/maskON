"""The HTTP service (FastAPI). Needs the extra: pip install "maskon[api]"."""

try:
    import fastapi  # noqa: F401
    import prometheus_client  # noqa: F401
except ImportError as error:  # pragma: no cover - exercised in a subprocess
    raise ImportError(
        'maskon.api needs the HTTP extra: pip install "maskon[api]"'
    ) from error
