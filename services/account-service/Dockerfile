FROM golang:alpine AS builder

WORKDIR /app
COPY . .
RUN go mod tidy
# Compile the API server
RUN go build -o main ./cmd/api

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .

EXPOSE 8080
CMD ["./main"]
