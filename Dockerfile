# syntax=docker/dockerfile:1.7

# --- build stage ----------------------------------------------------------
# Note: mutecomm/go-sqlcipher is a CGO wrapper around bundled SQLCipher, so
# we must enable CGO and include a C toolchain in the build stage.
FROM golang:1.25-bookworm AS build
WORKDIR /src

# Install build tools (gcc, libc-dev) for CGO; Go is already in the base image.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Cache deps separately from sources.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=v0.0.1
ARG COMMIT=dev
ENV CGO_ENABLED=1
# Force static linking so the binary runs on distroless/static (which has
# no glibc). CGO is required by go-sqlcipher; static glibc via
# -extldflags "-static" is the canonical workaround.
RUN go build \
      -tags 'sqlite_fts5' \
      -trimpath -buildvcs=true \
      -ldflags="-s -w -extldflags '-static' -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/scopuli ./cmd/scopuli

# --- runtime stage --------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
# Distroless has no /usr/local/bin; copy the binary to /scopuli.
COPY --from=build /out/scopuli /scopuli

# Run as the distroless nonroot user (UID 65532). The host directory
# mounted at /data must be writable by 65532. With a named volume
# (docker-compose) Docker creates it with the container's UID. With a bind
# mount, the operator must `chown 65532:65532` the host dir first; see
# docs/OPERATIONS.md.
USER 65532:65532

ENV SCOPULI_BIND=0.0.0.0:8080 \
    SCOPULI_DB_PATH=/data/vault.db \
    SCOPULI_LOG_LEVEL=info

EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["/scopuli"]
CMD ["serve"]
