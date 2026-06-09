FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o antifraud-service ./cmd/api

FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/antifraud-service .

EXPOSE 8080
CMD ["./antifraud-service"]
