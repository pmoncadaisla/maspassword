# Multi-arch build (linux/amd64, linux/arm64). The builder always runs on the
# host's native platform and cross-compiles Go for $TARGETARCH, so buildx does
# not need to emulate the compiler under QEMU.
#
# BuildKit injects BUILDPLATFORM; the default below is only for non-BuildKit
# builders (Cloud Build's classic docker builder, used by gcloud builds submit),
# where the variable would otherwise be empty and break the FROM line.
ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-s -w" -o server ./cmd/server

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
