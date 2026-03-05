#!/bin/bash
set -e

APP_NAME="ddos-martummai"
APP_USER="ddos-martummai"
APP_DIR="/opt/$APP_NAME"
CONFIG_DIR="/etc/$APP_NAME"
LOG_DIR="/var/log/$APP_NAME"
DATA_DIR="/var/lib/$APP_NAME"

echo "[*] Creating dedicated system user '$APP_USER'..."
# Create the user only if it doesn't already exist.
# --system: creates a system account (no password expiration, etc.)
# --no-create-home & --shell /usr/sbin/nologin: prevents actual logins for security
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$APP_USER"
fi

echo "[*] Setting up directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$DATA_DIR/cic" "$DATA_DIR/upload_queue"

echo "[*] Setting ownership and permissions for Privilege Separation..."
# The dedicated user MUST own these directories to read configs and write logs/data
chown -R root:root "$APP_DIR"
chmod 755 "$APP_DIR"

chown -R root:"$APP_USER" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

chown -R "$APP_USER:$APP_USER" "$LOG_DIR"
chmod 2770 "$LOG_DIR"

chown -R "$APP_USER:$APP_USER" "$DATA_DIR"
chmod 2770 "$DATA_DIR"
chmod 2770 "$DATA_DIR/cic"
chmod 2770 "$DATA_DIR/upload_queue"

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
    export UV_PYTHON_INSTALL_DIR="$APP_DIR/.python-versions"
    export UV_CACHE_DIR="$APP_DIR/.uv-cache"
    # Run uv sync. This will create the .venv directory
    uv sync --frozen
    
    # VERY IMPORTANT: Since root ran 'uv sync', the .venv belongs to root.
    # We must change its ownership to our dedicated user so the app can use it.
    echo "[*] Fixing virtual environment ownership..."
    chown -R "$APP_USER:$APP_USER" "$APP_DIR/.venv"
    
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
