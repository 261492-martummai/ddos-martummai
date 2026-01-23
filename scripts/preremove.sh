#!/bin/sh
set -e

# $1 = (remove, upgrade, deconfigure)
if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
    if command -v systemctl >/dev/null; then
        echo "Stopping ddos-martummai service..."
        systemctl stop ddos-martummai.service || true
        systemctl disable ddos-martummai.service || true
    fi
fi