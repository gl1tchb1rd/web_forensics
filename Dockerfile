# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DJANGO_SETTINGS_MODULE=webforensics.settings
WORKDIR /app

COPY requirements.txt ./
# Optional trust bundle for build environments with a TLS proxy. No CA is baked in.
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then \
      PIP_CERT=/run/secrets/proxy_ca pip install --no-cache-dir -r requirements.txt; \
    else \
      pip install --no-cache-dir -r requirements.txt; \
    fi

COPY webforensics ./webforensics
COPY forensics ./forensics
COPY templates ./templates
COPY static ./static
COPY manage.py gunicorn.conf.py LICENSE ./
RUN chmod -R a+rX /app

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:8000/healthz', timeout=2).read()"]
CMD ["gunicorn", "--config", "gunicorn.conf.py", "webforensics.wsgi:application"]
