# Standalone Ryu Mail service. Dokploy builds this file from the repository root
# so the sidecar keeps its narrow path dependencies without importing Core.

FROM rust:1-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
		build-essential \
		pkg-config \
		libssl-dev \
		ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY crates/core/crypto ./crates/core/crypto
COPY crates/core/sidecar-runtime ./crates/core/sidecar-runtime
COPY crates/core/app-events ./crates/core/app-events
COPY apps-store/mail/backend ./apps-store/mail/backend

WORKDIR /src/apps-store/mail/backend
RUN cargo build --release \
	&& cp target/release/ryu-mail /usr/local/bin/ryu-mail

FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
		ca-certificates \
		curl \
		libssl3 \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/ryu-mail /usr/local/bin/ryu-mail

ENV RYU_MAIL_MODE=standalone
ENV RYU_MAIL_HOSTNAME=0.0.0.0
ENV RYU_MAIL_PORT=7996
ENV RYU_DIR=/data

VOLUME ["/data"]
EXPOSE 7996

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
	CMD ["/bin/sh", "-c", "curl -fsS http://127.0.0.1:7996/api/mail/status || exit 1"]

ENTRYPOINT ["ryu-mail"]
