# Registry index digest verified against registry-1.docker.io on 2026-11-20.
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    AEGIS_ENV=production AEGIS_DEMO_PUBLIC=1 AEGIS_WORKERS=1 \
    AEGIS_PRODUCTION_HOST=0.0.0.0 AEGIS_PRODUCTION_DATA_DIR=/data/aegis \
    PORT=8080 TMPDIR=/data/tmp HOME=/data
WORKDIR /app
COPY requirements-production.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements-production.lock \
    && useradd --no-create-home --uid 10001 aegis \
    && mkdir -p /data && chown 10001:10001 /data
# Ship only the isolated entrypoint, never legacy executors.
COPY aegis/__init__.py aegis/production.py aegis/public_evaluator.py aegis/claims.py aegis/policy.py aegis/sensitivity.py aegis/mixed_demo.py ./aegis/
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.getenv('PORT','8080')+'/readyz',timeout=3)"
CMD ["python", "-m", "aegis.production"]
