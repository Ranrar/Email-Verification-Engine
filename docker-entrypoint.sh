#!/bin/bash
set -e

echo "Email Verification Engine - Docker Startup"
echo "=========================================="

# Copy Docker environment file to the expected location
if [ -f "/app/src/database/key.env.docker" ]; then
    echo "Setting up Docker database configuration..."
    cp /app/src/database/key.env.docker /app/src/database/key.env
fi

# Wait for PostgreSQL to be ready using pg_isready (simpler and more reliable)
echo "Waiting for PostgreSQL to be ready..."
until pg_isready -h postgres -p 5432 -U postgres; do
    echo "PostgreSQL is not ready yet, waiting 2 seconds..."
    sleep 2
done

echo "PostgreSQL is ready! Starting Email Verification Engine..."
exec python main.py