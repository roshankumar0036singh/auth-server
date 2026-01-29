# Build Stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0 for static binary, -ldflags="-w -s" to reduce size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o auth-server ./cmd/server

# Final Stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies (ca-certificates for HTTPS, tzdata for timezones)
RUN apk add --no-cache ca-certificates tzdata

# Create a non-root user
RUN addgroup -S authgroup && adduser -S authuser -G authgroup

# Copy binary from builder
COPY --from=builder /app/auth-server .
COPY --from=builder /app/templates ./templates
# Copy .env.example as .env template if needed, but usually .env is mounted
# COPY --from=builder /app/.env.example ./

# Set ownership
RUN chown -R authuser:authgroup /app

# Use non-root user
USER authuser

# Expose port
EXPOSE 8080

# Run application
CMD ["./auth-server"]
