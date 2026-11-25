# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && addgroup --system audit \
    && adduser --system --ingroup audit --home /app audit \
    && mkdir -p /var/lib/audit \
    && chown -R audit:audit /app /var/lib/audit

COPY --chown=audit:audit app ./app
USER audit
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
