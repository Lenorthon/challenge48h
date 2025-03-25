# Utiliser l'image Go officielle (ici Alpine pour la légèreté)
FROM golang:1.20-alpine

WORKDIR /app

# Copier les fichiers de gestion des modules
COPY go.mod go.sum ./
RUN go mod download

# Copier l'ensemble du code source dans le container
COPY . .

# Compiler l'application
RUN go build -o forum .

# Exposer le port 8080
EXPOSE 8080

# Lancer l'application
CMD ["./forum"]
