#!/bin/bash

# Exit immediately if a command fails
set -e

echo "🚫 Stopping old containers..."
docker compose down

echo "🔧 Building and starting Docker containers..."
docker compose up --build -d

echo "✅ Containers are up and running!"
