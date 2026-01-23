#!/bin/bash

APP_NAME="ddos-martummai"
INSTALL_DIR="/opt/$APP_NAME"
CONFIG_DIR="/etc/$APP_NAME"
LOG_DIR="/var/log/$APP_NAME"
SERVICE_NAME="$APP_NAME.service"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[*] Starting DDoS MarTumMai Installation...${NC}"

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (sudo ./install.sh)${NC}"
  exit 1
fi

# 2. System Dependencies
echo -e "${GREEN}[*] Installing system libraries...${NC}"
apt-get update
apt-get install -y libpcap-dev python3-pip curl git iptables build-essential

# 3. Install uv
if ! command -v uv &> /dev/null; then
    echo -e "${GREEN}[*] Installing uv package manager...${NC}"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source $HOME/.cargo/env
else
    echo -e "${GREEN}[*] uv is already installed.${NC}"
fi

# 4. Prepare Directories
echo -e "${GREEN}[*] Setting up directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# 5. Copy Application Files
echo -e "${GREEN}[*] Copying application files...${NC}"
# Copy entire src folder (includes models)
cp -r src "$INSTALL_DIR/"
cp pyproject.toml "$INSTALL_DIR/"
cp uv.lock "$INSTALL_DIR/" 2>/dev/null || true # Copy lock file if exists

# Copy Service File
cp system/$SERVICE_NAME /etc/systemd/system/

# Copy Default Config (Only if not exists)
if [ ! -f "$CONFIG_DIR/config.yml" ]; then
    cp config/config.yml "$CONFIG_DIR/"
fi

# 6. Install Python Deps (Sync)
echo -e "${GREEN}[*] Syncing Python environment...${NC}"
cd "$INSTALL_DIR"
/root/.cargo/bin/uv sync

# 7. Enable Service
echo -e "${GREEN}[*] Reloading Systemd...${NC}"
systemctl daemon-reload
systemctl enable $SERVICE_NAME

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN} INSTALLATION COMPLETE ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "1. Run configuration wizard:"
echo -e "   cd $INSTALL_DIR && uv run ddos-martummai"
echo -e "2. Start the service:"
echo -e "   systemctl start $SERVICE_NAME"
echo -e "${GREEN}==============================================${NC}"