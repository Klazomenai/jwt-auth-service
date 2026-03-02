# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o jwt-server ./cmd/server

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates && \
    mkdir -p /etc/jwt-service && \
    chown nobody:nobody /etc/jwt-service && \
    chmod 0700 /etc/jwt-service

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/jwt-server .

# Run as non-root
USER 65534

# Expose port
EXPOSE 8080

# Run the server
CMD ["./jwt-server"]
