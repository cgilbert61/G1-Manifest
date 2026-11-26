FROM python:3.12-alpine AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN apk update \
    && apk upgrade --no-cache \
    && apk add --no-cache gcc musl-dev linux-headers

COPY pyproject.toml requirements.txt README.md LICENSE ./
COPY estate_graph ./estate_graph

RUN pip install --no-cache-dir --prefix=/install ".[host]"


FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk update \
    && apk upgrade --no-cache \
    && adduser -D -u 1000 -s /sbin/nologin appuser \
    && mkdir -p /data/views /data/keys \
    && chown -R appuser:appuser /app /data

COPY --from=builder /install /usr/local
COPY examples ./examples

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)" || exit 1

CMD ["estate-graph", "serve", "--dir", "/data/views", "--host", "0.0.0.0", "--port", "8080", "--demo"]
