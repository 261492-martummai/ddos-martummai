#!/bin/bash
set -e

GITHUB_USER="261492-martummai"
GITHUB_REPO="ddos-martummai"
BINARY_NAME="ddos-martummai"

GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}[*] DDoS MarTumMai Installer${NC}"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or use sudo"
  exit 1
fi

DESIRED_VERSION=$1

if [ -z "$DESIRED_VERSION" ]; then
    echo "Checking latest version..."
    DESIRED_VERSION=$(curl -s "https://api.github.com/repos/$GITHUB_USER/$GITHUB_REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [ -z "$DESIRED_VERSION" ]; then
        echo "Error: Could not find latest release on GitHub."
        exit 1
    fi
fi

echo -e "Target Version: ${GREEN}$DESIRED_VERSION${NC}"

CLEAN_VERSION=$(echo "$DESIRED_VERSION" | sed 's/^v//') 
DEB_FILENAME="${BINARY_NAME}_${CLEAN_VERSION}_amd64.deb"
DOWNLOAD_URL="https://github.com/$GITHUB_USER/$GITHUB_REPO/releases/download/$DESIRED_VERSION/$DEB_FILENAME"

TEMP_DEB="/tmp/$DEB_FILENAME"
echo "Downloading from: $DOWNLOAD_URL"
curl -L -o "$TEMP_DEB" "$DOWNLOAD_URL"

if [ ! -f "$TEMP_DEB" ]; then
    echo "Error: Download failed."
    exit 1
fi

echo "Installing..."
apt install "$TEMP_DEB" -y --allow-downgrades

rm "$TEMP_DEB"

echo -e "${GREEN}Installation Complete!${NC}"