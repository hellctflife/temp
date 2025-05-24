# 1) Frontend builder
# FROM node:alpine AS frontend-builder

# WORKDIR /editor

# COPY editor/frontend/package*.json ./
# RUN npm install
# COPY editor/frontend/ ./
#  RUN npm run build

# 2) Final runtime should be a Golang
FROM golang:alpine AS final-build
WORKDIR /app

# Create non-root users
RUN addgroup -S challenger && adduser -S challenger -G challenger \
    && addgroup -S editor \
    && adduser -S editor -G editor -s /bin/bash && addgroup editor challenger

# Add password for root (hidden)
RUN echo "root:XXXXXXXXXXXXXXXXXXXXXXXXXXXX" | chpasswd && chmod ug+s /bin/su


# Install dependencies 
RUN apk add --no-cache nginx supervisor bash  postgresql postgresql-client git gcc postgresql-dev musl-dev
# RUN apk add python3 py3-pip python3-dev 
# RUN pip install --break-system-packages --no-cache-dir flask requests psycopg2 semgrep aiohttp

# Copy the entire application directory structure with correct ownership
RUN mkdir -p /app/golang && chown -R editor:challenger /app/golang
WORKDIR /app/golang
COPY --chown=editor:challenger challenge/application/ ./

# Set GOPRIVATE to prevent Go from trying to fetch modules from GitHub
ENV GOPRIVATE=github.com/atomic-protocol/*

# Build the application with the local modules
USER editor
ENV GOCACHE=/tmp/go-build
RUN go mod tidy &&  go build -o ./atomic-protocol ./cmd/server


# Create PostgreSQL directory but don't initialize it
USER root
RUN mkdir -p /var/lib/postgresql/data
RUN chown -R postgres:postgres /var/lib/postgresql/data

# Set PostgreSQL environment variables
ENV POSTGRES_USER postgres
ENV POSTGRES_PASSWORD password
ENV POSTGRES_DB atomic_protocol

# Copy files from builders
# WORKDIR /app
# COPY editor/backend/ ./backend
# COPY --from=frontend-builder /editor/dist       ./backend/static

# Set permissions
RUN chown -R editor:challenger /app/golang
# RUN chown -R editor:editor      /app/backend

# Fix permissions (no cheeky SSTI)
RUN chmod -R 404 /app/golang/go.sum /app/golang/go.mod
RUN chmod -R 555 /app/golang/templates /app/golang/static /app/golang/cmd /app/golang/internal/config /app/golang/internal/db/database.go
# RUN chmod -R 770 /app/backend
RUN chmod -R 740 /app/golang/internal /app/golang/pkg

# Configure the application
RUN mkdir -p /etc/supervisor.d
COPY config/supervisord.conf  /etc/supervisor.d/supervisord.ini
RUN chmod 660 /etc/supervisor.d/supervisord.ini

COPY config/nginx.conf       /etc/nginx/nginx.conf
RUN chown -R root:editor /etc/nginx/nginx.conf && chmod 660 /etc/nginx/nginx.conf
COPY config/proxy_params    /etc/nginx/proxy_params

COPY flag.txt                /flag.txt

# Environment
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 1337
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]