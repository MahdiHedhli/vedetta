FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o /vedetta ./cmd/vedetta

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /vedetta /usr/local/bin/vedetta

EXPOSE 8080
ENTRYPOINT ["vedetta"]
