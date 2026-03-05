#!/bin/bash

APP_DIR="/etc/ddos-martummai"

if [ "$1" = "purge" ]; then
    echo "[*] Removing generated config..."
    rm -f "$APP_DIR/config.yml"
fi

exit 0