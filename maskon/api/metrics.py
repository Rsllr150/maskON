"""Prometheus metrics.

Lives in the API layer (an ops concern) so the detection core stays free of any
web/observability dependency. Imported and updated by the route handlers.
"""

from prometheus_client import Counter, Histogram

REQUESTS = Counter(
    "maskon_requests_total",
    "Number of API requests handled, by endpoint.",
    ["endpoint"],
)

FINDINGS = Counter(
    "maskon_findings_total",
    "Number of PII findings produced, by type.",
    ["type"],
)

BYTES = Counter(
    "maskon_bytes_processed_total",
    "Total bytes of input text processed.",
)

LATENCY = Histogram(
    "maskon_request_duration_seconds",
    "Request handling latency, by endpoint.",
    ["endpoint"],
)
