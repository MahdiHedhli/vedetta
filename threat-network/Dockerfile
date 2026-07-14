FROM golang:1.26-alpine AS builder

# mattn/go-sqlite3 requires CGO (matches the Core backend's SQLite driver).
RUN apk --no-cache add gcc musl-dev

WORKDIR /app
COPY go.mod go.sum* ./
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /threat-network ./cmd/threat-network

FROM alpine:3.24
# sqlite supplies the online .backup command used by the documented corpus/feed
# recovery procedure; it is not used on the HTTP request path.
RUN apk --no-cache add ca-certificates sqlite
COPY --from=builder /threat-network /usr/local/bin/threat-network

# Service-local SQLite DB lives here; mount a volume for persistence.
ENV THREAT_NETWORK_DB=/data/threat-network.db
VOLUME ["/data"]

EXPOSE 9090
ENTRYPOINT ["threat-network"]
