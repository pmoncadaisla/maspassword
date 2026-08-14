# Multi-arch build (linux/amd64, linux/arm64). The builder always runs on the
# host's native platform and cross-compiles Go for $TARGETARCH, so buildx does
# not need to emulate the compiler under QEMU.
#
# Requires BuildKit ($BUILDPLATFORM is injected by it). For Cloud Build, use
# cloudbuild.yaml, which enables BuildKit — the classic builder fails here.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-s -w -X main.version=${VERSION}" -o server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 vault
WORKDIR /app
COPY --from=builder /app/server .
COPY --from=builder /app/web ./web
COPY --from=builder /app/internal/database/migrations ./internal/database/migrations
USER vault
EXPOSE 8080
CMD ["./server"]
