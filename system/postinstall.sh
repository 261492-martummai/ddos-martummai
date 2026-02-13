#!/bin/bash

mkdir -p /var/log/ddos-martummai
mkdir -p /var/lib/ddos-martummai
mkdir -p /etc/ddos-martummai

chmod 750 /etc/ddos-martummai
chmod 750 /var/log/ddos-martummai
chmod 750 /var/lib/ddos-martummai

cd /opt/ddos-martummai

if ! command -v uv &> /dev/null; then
    echo "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi

export PATH="/root/.local/bin:/root/.cargo/bin:$PATH"

echo "Load DDoS MarTumMai Dependencies..."
/root/.cargo/bin/uv sync --frozen

systemctl daemon-reload

echo "========================================================"
echo "  DDoS MarTumMai Installed Successfully!"
echo "========================================================"
echo "PLEASE RUN THE SETUP WIZARD FIRST:"
echo "   sudo martummai-setup"
echo ""
echo "Then start the service:"
echo "   sudo systemctl start ddos-martummai"
echo "========================================================"