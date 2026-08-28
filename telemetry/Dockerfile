FROM golang:1.27-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o /telemetry ./cmd/telemetry

FROM alpine:3.24
RUN apk --no-cache add ca-certificates

# Persisted telemetry state (cursor, reporter identity, salt, spool). All files
# are node-local; secrets (reporter.json, salt) are written 0600. Mount a volume
# here so opt-in registration and the poll cursor survive restarts.
ENV VEDETTA_TELEMETRY_STATE_DIR=/var/lib/vedetta-telemetry
VOLUME ["/var/lib/vedetta-telemetry"]

# Localhost status/health surface (/healthz, /status). Bind to 127.0.0.1 inside
# the container; map to localhost only on the host if you want to inspect it.
ENV VEDETTA_TELEMETRY_STATUS_ADDR=127.0.0.1:9091
EXPOSE 9091

COPY --from=builder /telemetry /usr/local/bin/telemetry

ENTRYPOINT ["telemetry"]
