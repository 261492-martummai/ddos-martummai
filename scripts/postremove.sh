#!/bin/sh
set -e

if [ "$1" = "purge" ] || [ "$1" = "remove" ]; then
    echo "Cleaning up application files..."
    rm -rf /opt/ddos-martummai
    
    if command -v systemctl >/dev/null; then
        systemctl daemon-reload || true
    fi
fi