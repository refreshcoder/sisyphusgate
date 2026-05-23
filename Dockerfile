ARG PYTHON_VERSION=3.11-slim

FROM python:${PYTHON_VERSION} AS builder

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir .

FROM python:${PYTHON_VERSION} AS runtime

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=0.1.1

LABEL org.opencontainers.image.title="SisyphusGate" \
      org.opencontainers.description="Modular honeypot system for malicious traffic detection, analysis, routing and data aggregation" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.authors="SisyphusGate Team" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/refreshcoder/sisyphusgate" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="docker.io/library/python:${PYTHON_VERSION}" \
      org.opencontainers.image.ref.name="sisyphusgate" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="SisyphusGate" \
      org.opencontainers.image.documentation="https://github.com/refreshcoder/sisyphusgate#readme"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash --no-log-init --uid 1000 sisyphus

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /app

COPY config/ ./config/
RUN mkdir -p logs data

RUN chown -R sisyphus:sisyphus /app

USER sisyphus

EXPOSE 2222 2323 8080

ENV SISYPHUSGATE_CONFIG=/app/config/docker.yaml
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('127.0.0.1',2222)); s.close()" || exit 1

ENTRYPOINT ["python", "-m", "sisyphusgate"]
CMD ["run"]
