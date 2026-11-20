FROM python:3.12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
ARG AEGIS_REF
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /src
COPY pyproject.toml ./
COPY src ./src
RUN test -n "$AEGIS_REF" \
    && pip install --no-cache-dir ".[api,aws,gemini]" \
    && pip install --no-cache-dir "git+https://github.com/achh-914/AEGIS.git@${AEGIS_REF}"

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 hybrid \
    && mkdir /data && chown hybrid /data
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    HYBRID_DB=/data/hybrid.db \
    PYTHONUNBUFFERED=1
USER hybrid
VOLUME /data
EXPOSE 8000
CMD ["uvicorn", "hybrid.api:create_default_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
