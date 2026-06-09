FROM golang:1.22-alpine AS builder

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /app

COPY . .
RUN go mod tidy
RUN go mod download

RUN go build -o main ./cmd/api

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/main .

EXPOSE 8080
CMD ["./main"]
