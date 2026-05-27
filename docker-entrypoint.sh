#!/bin/bash
set -e

# Fix permissions for mounted volumes at runtime (running as root initially)
# This handles cases where host directories are owned by root (common on Unraid)
mkdir -p /app/logs /app/data
chown -R sisyphus:sisyphus /app/logs /app/data 2>/dev/null || true
chmod 755 /app/logs /app/data

# Drop privileges and execute the main command
exec gosu sisyphus "$@"
