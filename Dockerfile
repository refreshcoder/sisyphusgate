ARG PYTHON_VERSION=3.11-slim

FROM python:${PYTHON_VERSION}

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash --no-log-init --uid 1000 sisyphus

COPY pyproject.toml .
COPY src/ src/
COPY config/ config/

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

RUN mkdir -p logs data && \
    chown -R sisyphus:sisyphus /app

USER sisyphus

EXPOSE 2222 2323 8080

ENV SISYPHUSGATE_CONFIG=/app/config/docker.yaml
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "sisyphusgate"]
CMD ["run"]
