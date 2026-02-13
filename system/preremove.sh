#!/bin/bash

SERVICE_NAME="ddos-martummai.service"
APP_DIR="/opt/ddos-martummai"

if command -v systemctl >/dev/null 2>&1; then
    echo "Stopping $SERVICE_NAME..."
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl disable $SERVICE_NAME 2>/dev/null || true
fi

if [ -d "$APP_DIR/.venv" ]; then
    echo "Removing virtual environment..."
    rm -rf "$APP_DIR/.venv"
fi

if [ -d "$APP_DIR/__pycache__" ]; then
    rm -rf "$APP_DIR/__pycache__"
fi