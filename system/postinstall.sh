#!/bin/bash
set -e

APP_NAME="ddos-martummai"
APP_DIR="/opt/$APP_NAME"
CONFIG_DIR="/etc/$APP_NAME"
LOG_DIR="/var/log/$APP_NAME"
DATA_DIR="/var/lib/$APP_NAME"

echo "[*] Setting up directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR"

chown -R root:root "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR" "$APP_DIR"
chmod 750 "$CONFIG_DIR"
chmod 750 "$LOG_DIR"
chmod 750 "$DATA_DIR"

export PATH="/root/.local/bin:/root/.cargo/bin:$PATH"

if ! command -v uv &> /dev/null; then
    echo "[*] Installing uv package manager..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
else
    echo "[*] uv is already installed."
fi

echo "[*] Load DDoS MarTumMai Dependencies..."
if [ -d "$APP_DIR" ]; then
    cd "$APP_DIR" || exit 1
    uv sync --frozen
else
    echo "Error: Application directory $APP_DIR not found!"
    exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
    echo "[*] Reloading systemd..."
    systemctl daemon-reload
    systemctl reset-failed "$APP_NAME" 2>/dev/null || true
fi

echo "==========================================="
echo "  DDoS MarTumMai Installed Successfully!"
echo "==========================================="
echo "PLEASE RUN THE SETUP WIZARD FIRST:"
echo "   sudo ddos-martummai --setup"
echo ""
echo "Then start the service:"
echo "   sudo systemctl start $APP_NAME"
echo ""
echo "If you want to enable it to start on boot:"
echo "   sudo systemctl enable $APP_NAME"
echo ""
echo "Check status:"
echo "   sudo systemctl status $APP_NAME"
echo "==========================================="

exit 0
