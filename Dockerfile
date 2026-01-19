# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build arguments for version info
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION} -X main.gitCommit=${GIT_COMMIT} -X main.buildDate=${BUILD_DATE} -s -w" \
    -o sentinel ./cmd/sentinel

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    docker-cli \
    && rm -rf /var/cache/apk/*

# Create non-root user for running scans
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

# Copy binary from builder
COPY --from=builder /app/sentinel /usr/local/bin/sentinel

# Copy default policies
COPY configs/policies /etc/sentinel/policies

# Create directories
RUN mkdir -p /etc/sentinel/audit /etc/sentinel/cache \
    && chown -R sentinel:sentinel /etc/sentinel

# Set working directory
WORKDIR /workspace

# Default entrypoint
ENTRYPOINT ["sentinel"]

# Default command (show help)
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="Docker Sentinel" \
      org.opencontainers.image.description="Pre-runtime container security for Docker" \
      org.opencontainers.image.vendor="rtvkiz" \
      org.opencontainers.image.source="https://github.com/rtvkiz/docker-sentinel" \
      org.opencontainers.image.licenses="MIT"
