#!/bin/bash

# Ensure log directory exists
mkdir -p /var/log/ddos-martummai

# Install uv if not present
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi

cd /opt/ddos-martummai
if [ -f "/root/.cargo/bin/uv" ]; then
    /root/.cargo/bin/uv sync
else
    ~/.cargo/bin/uv sync
fi

systemctl daemon-reload