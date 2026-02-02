# Build stage
FROM golang:1.22-alpine AS builder

# Install base packages
RUN apk add --no-cache git tzdata ca-certificates

WORKDIR /app

# Download dependencies
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
# -ldflags="-w -s" to strip debug information and reduce binary size
# -o /go/bin/aml-service the output path
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /go/bin/aml-service ./cmd/server

# Final stage
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /

# Copy the binary from builder
COPY --from=builder /go/bin/aml-service /aml-service

# Copy CA certificates if needed (distroless includes them, but explicit copy from builder is safe too if using alpine as base for runner)
# Distroless static already has them.

# Run as non-root user (provided by distroless)
USER nonroot:nonroot

# Expose ports
EXPOSE 8084 9094

# Command to run
ENTRYPOINT ["/aml-service"]
