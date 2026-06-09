FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o main ./cmd/api

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 8080
CMD ["./main"]
