#!/usr/bin/env bash
# Tear down the UniFi integration test environment and remove all data.
set -euo pipefail
cd "$(dirname "$0")"

echo "Stopping containers and removing volumes..."
docker compose down -v

echo "Cleaning up .env..."
rm -f .env

echo "Done."
