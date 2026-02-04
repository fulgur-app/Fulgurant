# Build stage
FROM rust:1.93-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    openssl-dev \
    openssl-libs-static

# Set working directory
WORKDIR /build

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create a dummy main to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs

# Build dependencies only (this layer will be cached)
RUN cargo build --release && \
    rm -rf src

# Copy the actual source code
COPY src ./src
COPY templates ./templates
COPY data/migrations ./data/migrations
# COPY test_tools ./test_tools

# Build the application
# Touch main.rs to force rebuild of our code (dependencies are cached)
RUN touch src/main.rs && \
    cargo build --release --bin Fulgurant

# Runtime stage
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    wget \
    && addgroup -g 1000 fulgurant \
    && adduser -D -u 1000 -G fulgurant fulgurant

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/target/release/Fulgurant /app/fulgurant

# Copy runtime assets
COPY --from=builder /build/templates /app/templates
COPY --from=builder /build/data/migrations /app/data/migrations
COPY assets /app/assets

# Copy entrypoint script
COPY docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

# Create data directory with proper permissions
RUN mkdir -p /data/logs && \
    chown -R fulgurant:fulgurant /data /app

# Environment variables with defaults
ENV DATABASE_URL=sqlite:/data/fulgurant.db \
    BIND_HOST=0.0.0.0 \
    BIND_PORT=3000 \
    IS_PROD=true \
    LOG_FOLDER=/data/logs \
    RUST_LOG=info \
    PUID=1000 \
    PGID=1000

# Expose port
EXPOSE 3000

# Volume for persistent data
VOLUME ["/data"]

# Switch to non-root user
USER fulgurant

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/ping || exit 1

# Set entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]
