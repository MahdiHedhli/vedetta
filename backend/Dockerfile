FROM golang:1.26-alpine AS builder

RUN apk --no-cache add gcc musl-dev

WORKDIR /app
COPY backend/go.mod backend/go.sum* ./
COPY backend/ .
COPY VERSION ./VERSION
RUN VERSION="$(cat VERSION)" && \
    test "$(wc -l < VERSION | tr -d ' ')" = "1" && \
    printf '%s' "$VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$' && \
    go mod tidy && \
    CGO_ENABLED=1 GOOS=linux go build -trimpath \
      -ldflags="-s -w -X main.buildVersion=${VERSION}" \
      -o /vedetta ./cmd/vedetta && \
    test "$(/vedetta --version)" = "vedetta-core ${VERSION}"

FROM alpine:3.24
RUN apk --no-cache add ca-certificates sqlite

COPY --from=builder /vedetta /usr/local/bin/vedetta
COPY siem/migrations /app/siem/migrations

EXPOSE 8080
ENTRYPOINT ["vedetta"]
