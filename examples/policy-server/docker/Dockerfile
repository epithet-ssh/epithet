# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o epithet ./cmd/epithet

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates curl

# Create non-root user
RUN addgroup -S epithet && adduser -S epithet -G epithet

# Copy binary from builder
COPY --from=builder /build/epithet /usr/local/bin/epithet

# Set ownership
RUN chown epithet:epithet /usr/local/bin/epithet

# Switch to non-root user
USER epithet

ENTRYPOINT ["/usr/local/bin/epithet"]
CMD ["--help"]
