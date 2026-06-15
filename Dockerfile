FROM python:3.12-slim

# Don't write .pyc files; stream logs straight out (no buffering).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install runtime dependencies first so this layer is cached when only code
# changes. Note: requirements.txt holds runtime deps only (no test/lint tools).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code (the package only — no tests, corpus or scripts).
COPY maskon ./maskon

# Run as an unprivileged user.
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "maskon.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
