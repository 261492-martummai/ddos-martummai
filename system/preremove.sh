#!/bin/bash

SERVICE_NAME="ddos-martummai.service"
APP_DIR="/opt/ddos-martummai"

if command -v systemctl >/dev/null 2>&1; then
    echo "Stopping $SERVICE_NAME..."
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl disable $SERVICE_NAME 2>/dev/null || true
fi

if [ -d "$APP_DIR" ]; then
    echo "Removing Python cache and generated files..."
    find $APP_DIR -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find $APP_DIR -type f -name "*.pyc" -delete 2>/dev/null || true

    rm -rf "$APP_DIR/.venv"
fi

exit 0