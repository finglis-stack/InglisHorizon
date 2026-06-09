FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ledger-service ./cmd/api

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/ledger-service .
EXPOSE 8483
CMD ["./ledger-service"]
