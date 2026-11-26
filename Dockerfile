FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml requirements.txt README.md LICENSE ./
COPY estate_graph ./estate_graph
COPY examples ./examples

RUN pip install --no-cache-dir ".[host]" \
    && useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /data/views /data/keys \
    && chown -R appuser:appuser /app /data

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)" || exit 1

CMD ["estate-graph", "serve", "--dir", "/data/views", "--host", "0.0.0.0", "--port", "8080", "--demo"]
