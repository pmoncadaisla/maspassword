#!/bin/bash
set -euo pipefail

DB_NAME="vault_internal"
DB_USER="vault_user"
DB_PASS="vault_pass"

echo "Creating PostgreSQL user and database..."

# Create user if not exists
psql postgres -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 || \
  psql postgres -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';"

# Create database if not exists
psql postgres -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 || \
  psql postgres -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"

# Grant privileges
psql postgres -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};"

# Enable uuid-ossp extension
psql "${DB_NAME}" -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";'

echo "Database setup complete!"
echo "Connection string: postgres://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}?sslmode=disable"
