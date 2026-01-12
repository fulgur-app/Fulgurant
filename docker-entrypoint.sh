#!/bin/sh
set -e

# Display startup information
echo "Starting Fulgurant..."
echo "Database: ${DATABASE_URL}"
echo "Bind address: ${BIND_HOST}:${BIND_PORT}"
echo "Production mode: ${IS_PROD}"
echo "Log folder: ${LOG_FOLDER}"

# Ensure data directory exists and is writable
if [ ! -d "/data" ]; then
    echo "ERROR: /data directory does not exist. Please mount a volume."
    exit 1
fi

if [ ! -w "/data" ]; then
    echo "ERROR: /data directory is not writable. Check volume permissions."
    exit 1
fi

# Create logs directory if it doesn't exist
mkdir -p "${LOG_FOLDER}"

# Create database directory if it doesn't exist
DB_DIR=$(dirname "${DATABASE_URL#sqlite:}")
mkdir -p "${DB_DIR}"

echo "Data directory ready"
echo "Starting application..."

# Execute the application
exec /app/fulgurant
