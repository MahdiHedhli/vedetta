FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o /telemetry ./cmd/telemetry

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /telemetry /usr/local/bin/telemetry

ENTRYPOINT ["telemetry"]
