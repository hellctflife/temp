#!/bin/sh

echo "127.0.0.1 atomic_protocol.htb" >> /etc/hosts

RNDOM1=$(cat /dev/urandom | tr -dc 'a-e0-9' | fold -w 32 | head -n 1)
FLAGNAME=$(echo "$RNDOM1.txt" | tr -d ' ')

chown root:editor /flag.txt
mv /flag.txt "/$FLAGNAME" && chmod 440 "/$FLAGNAME"

# Ensure PostgreSQL socket directory exists with correct permissions
mkdir -p /run/postgresql
chown postgres:postgres /run/postgresql
chmod 775 /run/postgresql

# PostgreSQL initialization
if [ ! -f /var/lib/postgresql/data/PG_VERSION ]; then
    echo "Initializing PostgreSQL database..."
    su postgres -c "initdb -D /var/lib/postgresql/data"
    
    # Update PostgreSQL configuration to use the socket directory
    echo "unix_socket_directories = '/run/postgresql'" >> /var/lib/postgresql/data/postgresql.conf
    echo "listen_addresses = 'localhost'" >> /var/lib/postgresql/data/postgresql.conf
fi

# Start PostgreSQL service
su postgres -c "pg_ctl -D /var/lib/postgresql/data start"

# Wait for PostgreSQL to be ready
RETRIES=5
until su postgres -c "psql -c '\l'" > /dev/null 2>&1 || [ $RETRIES -eq 0 ]; do
    echo "Waiting for PostgreSQL to start, $RETRIES remaining attempts..."
    RETRIES=$((RETRIES-1))
    sleep 1
done

# Create database and user if needed
if [ $RETRIES -ne 0 ]; then
    echo "PostgreSQL started successfully"
    su postgres -c "psql -c \"SELECT 1 FROM pg_database WHERE datname = '${POSTGRES_DB}'\" | grep -q 1 || psql -c \"CREATE DATABASE ${POSTGRES_DB}\"" || echo "Database already exists"
    su postgres -c "psql -c \"SELECT 1 FROM pg_roles WHERE rolname = '${POSTGRES_USER}'\" | grep -q 1 || psql -c \"CREATE USER ${POSTGRES_USER} WITH ENCRYPTED PASSWORD '${POSTGRES_PASSWORD}'\"" || echo "User already exists"
    su postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE ${POSTGRES_DB} TO ${POSTGRES_USER}\"" || echo "Privileges already granted"
else
    echo "Failed to start PostgreSQL"
fi

# Start supervisord which will manage all services
/usr/bin/supervisord -c /etc/supervisor.d/supervisord.ini