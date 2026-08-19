FROM ghcr.io/prefix-dev/pixi:latest AS builder

WORKDIR /app
COPY . .

# Install only the service feature, not dev. voms-proxy-init/-info/-destroy
# come from the conda-forge `voms` package (see pixi.toml) — unlike
# condor-token-service's condor_token_create, which needs an apt repo, the
# VOMS clients ride in the same pixi environment as the Python service, so
# no extra package-manager step is needed in the runtime stage below.
RUN pixi install --frozen --environment service

# Capture pixi's full activation (PATH, and anything else the environment
# needs) as a static entrypoint script, so the final image needs no pixi
# binary at runtime.
RUN echo '#!/bin/bash' > /app/entrypoint.sh && \
    pixi shell-hook --manifest-path /app/pixi.toml --environment service -s bash >> /app/entrypoint.sh && \
    echo 'exec "$@"' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Final stage: debian:bookworm-slim, matching condor-token-service's
# Containerfile.broker layout (and staying binary-compatible with the
# pixi-built environment copied from the builder stage). ca-certificates is
# needed at runtime for httpx to verify the broker's JWKS TLS endpoint.
# Grid trust is fully baked into the pixi environment: ca-policy-lcg (IGTF
# CA bundle, whose activation exports X509_CERT_DIR via the entrypoint),
# voms-lsc (vomsdir .lsc files), and the vomses shipped by the voms package
# itself — no mounts required. Refresh the trust bundle by re-releasing.
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Keep the same absolute path as the builder stage: the entrypoint script's
# activation exports (and any console-script shebangs, e.g. uvicorn) are
# baked in at this exact path, and relocating the env directory breaks them.
COPY --from=builder /app/.pixi/envs/service /app/.pixi/envs/service
COPY --from=builder /app/src /app/src
COPY --from=builder /app/entrypoint.sh /app/entrypoint.sh

ENV PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# No USER directive: the runtime uid/capabilities are governed by the Helm
# chart's podSecurityContext — reading arbitrary users' NFS-mounted
# ~/.globus/{usercert,userkey}.pem requires runAsUser 0 plus
# CAP_DAC_READ_SEARCH (see charts/voms-token-service/values.yaml).

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "voms_token_service.app:app", "--host", "0.0.0.0", "--port", "8080"]
