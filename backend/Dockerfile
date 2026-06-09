FROM golang:1.22-alpine AS builder

# Configuration de l'environnement
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /app

# Copie des fichiers et téléchargement des dépendances
COPY . .
# Utilisation de mod tidy pour s'assurer que go.mod et go.sum sont à jour
RUN go mod tidy
RUN go mod download

# Compilation
RUN go build -o main ./cmd/api

# Image finale ultra-légère
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .

EXPOSE 8080
CMD ["./main"]
