FROM python:3.12-slim

# Don't write .pyc files; stream logs straight out (no buffering).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install the package and its runtime dependencies from pyproject (dev extras
# are not installed, so the image stays lean — no pytest/ruff/mypy).
COPY pyproject.toml ./
COPY maskon ./maskon
RUN pip install --no-cache-dir .

# Run as an unprivileged user.
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "maskon.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
