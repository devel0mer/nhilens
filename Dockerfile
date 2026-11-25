# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X github.com/devel0mer/nhilens/internal/version.Version=${VERSION} -X github.com/devel0mer/nhilens/internal/version.Commit=${COMMIT} -X github.com/devel0mer/nhilens/internal/version.Date=${DATE}" \
    -o /out/nhilens ./cmd/nhilens

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/devel0mer/nhilens" \
      org.opencontainers.image.description="Strictly read-only Go CLI to audit AWS non-human identities (NHI) and AI agents" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /out/nhilens /usr/local/bin/nhilens
ENTRYPOINT ["/usr/local/bin/nhilens"]
