FROM python:3.13-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.13-slim

RUN groupadd --system secobserve \
    && useradd --system --gid secobserve --create-home secobserve

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels

USER secobserve
# Both SECOBSERVE_IMPORT_DIR and SECOBSERVE_EXPORT_DIR default to the working directory, and at / that
# makes exports unwritable and gives the upload confinement the whole filesystem as its root.
WORKDIR /home/secobserve

EXPOSE 8931

ENTRYPOINT ["secobserve-mcp"]
CMD ["--transport", "http", "--host", "0.0.0.0"]
