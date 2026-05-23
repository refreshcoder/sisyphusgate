#!/bin/bash
# SisyphusGate Unraid Deployment Script

set -e

echo "========================================="
echo "  SisyphusGate Unraid Deployer"
echo "========================================="
echo ""

# Check if SISYPHUSGATE_BASE is set in .env
if [ -f ".env" ]; then
    SISYPHUSGATE_BASE=$(grep -E "^SISYPHUSGATE_BASE=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'" | xargs)
fi

# If not set, use current directory
if [ -z "$SISYPHUSGATE_BASE" ]; then
    SISYPHUSGATE_BASE="."
fi

echo "Using base directory: $SISYPHUSGATE_BASE"
echo ""

# Create required directories
echo "Creating directories..."
mkdir -p "$SISYPHUSGATE_BASE/config/cowrie/etc"
mkdir -p "$SISYPHUSGATE_BASE/logs/sisyphusgate"
mkdir -p "$SISYPHUSGATE_BASE/logs/cowrie"
mkdir -p "$SISYPHUSGATE_BASE/data"
echo "Directories created successfully!"
echo ""

# Download cowrie.cfg if not exists
if [ ! -f "$SISYPHUSGATE_BASE/config/cowrie/etc/cowrie.cfg" ]; then
    echo "Downloading cowrie.cfg..."
    curl -fSL "https://raw.githubusercontent.com/refreshcoder/sisyphusgate/main/config/cowrie/etc/cowrie.cfg" -o "$SISYPHUSGATE_BASE/config/cowrie/etc/cowrie.cfg"
    echo "cowrie.cfg downloaded successfully!"
else
    echo "cowrie.cfg already exists, skipping download."
fi
echo ""

echo "========================================="
echo "  Setup complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Review and edit .env if needed"
echo "2. Run: docker compose up -d"
echo ""
