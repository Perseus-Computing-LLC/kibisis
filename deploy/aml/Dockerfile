# Kibisis AML Add/Search adapter, built from the checked-out commit.
#   docker build -f deploy/aml/Dockerfile --build-arg KIBISIS_COMMIT=$(git rev-parse HEAD) -t kibisis-aml .
FROM python:3.12-slim-bookworm

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . && rm -rf /build

ARG KIBISIS_COMMIT=""
ENV KIBISIS_AML_COMMIT=${KIBISIS_COMMIT} \
    KIBISIS_AML_DATA_DIR=/data \
    ARGUS_LEDGER_PATH="" \
    HOME=/tmp

WORKDIR /
VOLUME ["/data"]
EXPOSE 8080
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4)"]

ENTRYPOINT ["python", "-m", "kibisis", "aml-serve", "--host", "0.0.0.0", "--port", "8080"]
