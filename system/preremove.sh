#!/bin/bash

SERVICE_NAME="ddos-martummai.service"
APP_DIR="/opt/ddos-martummai"

# The $1 variable tells us the action apt is performing.
# We only want to stop services and delete environment files on "remove" or "purge",
# NOT during an "upgrade" to a newer version.
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    
    echo "[*] Stopping and disabling $SERVICE_NAME..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    fi

    if [ -d "$APP_DIR" ]; then
        echo "[*] Removing Python cache, virtual environment, and generated files..."
        find "$APP_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        find "$APP_DIR" -type f -name "*.pyc" -delete 2>/dev/null || true
        
        # Remove the virtual environment that we manually created in postinstall.sh
        rm -rf "$APP_DIR/.venv"
        rm -rf "$APP_DIR/.uv-cache"
        rm -rf "$APP_DIR/.python-versions"
    fi
fi

exit 0