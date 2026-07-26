# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base

# liboqs-python requires the liboqs C library to be built/present; a real
# build additionally compiles liboqs here or installs a prebuilt package.
# See DECISIONS.md for the exact liboqs version pinned for Grade A.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake ninja-build git libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[dev]"

COPY src ./src
COPY alembic.ini ./
COPY alembic ./alembic

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
