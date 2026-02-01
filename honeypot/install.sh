#!/bin/bash

# Honeypot Client Installation Script
# This script installs and configures the honeypot client

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
HONEYPOT_DIR="/opt/honeypot"
HONEYPOT_USER="honeypot"
SERVER_URL="${SERVER_URL:-}"
HONEYPOT_ID="${HONEYPOT_ID:-}"

echo -e "${GREEN}[*] Honeypot Client Installation Script${NC}"
echo -e "${YELLOW}[*] Starting installation...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] This script must be run as root${NC}"
    exit 1
fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --server-url)
            SERVER_URL="$2"
            shift 2
            ;;
        --honeypot-id)
            HONEYPOT_ID="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}[!] Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Validate required parameters
if [ -z "$SERVER_URL" ] || [ -z "$HONEYPOT_ID" ]; then
    echo -e "${RED}[!] Missing required parameters${NC}"
    echo "Usage: $0 --server-url <url> --honeypot-id <id>"
    exit 1
fi

echo -e "${GREEN}[+] Server URL: $SERVER_URL${NC}"
echo -e "${GREEN}[+] Honeypot ID: $HONEYPOT_ID${NC}"

# Update system packages
echo -e "${YELLOW}[*] Updating system packages...${NC}"
apt-get update
apt-get install -y python3 python3-pip python3-venv git

# Create honeypot user
if ! id "$HONEYPOT_USER" &>/dev/null; then
    echo -e "${YELLOW}[*] Creating honeypot user...${NC}"
    useradd -r -s /bin/bash -d "$HONEYPOT_DIR" "$HONEYPOT_USER" || true
fi

# Create honeypot directory
echo -e "${YELLOW}[*] Creating honeypot directory...${NC}"
mkdir -p "$HONEYPOT_DIR"
mkdir -p "$HONEYPOT_DIR/logs"
mkdir -p "$HONEYPOT_DIR/config"

# Create virtual environment
echo -e "${YELLOW}[*] Creating Python virtual environment...${NC}"
python3 -m venv "$HONEYPOT_DIR/venv"

# Activate virtual environment and install dependencies
echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
source "$HONEYPOT_DIR/venv/bin/activate"
pip install --upgrade pip
pip install honeypots requests pyyaml

# Create configuration file
echo -e "${YELLOW}[*] Creating configuration file...${NC}"
cat > "$HONEYPOT_DIR/config/honeypot.conf" <<EOF
SERVER_URL=${SERVER_URL}
HONEYPOT_ID=${HONEYPOT_ID}
LOG_DIR=${HONEYPOT_DIR}/logs
CONFIG_DIR=${HONEYPOT_DIR}/config
HOSTNAME=$(hostname)
PLATFORM=$(uname -s)
EOF

# Set permissions
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR"
chmod 750 "$HONEYPOT_DIR"
chmod 640 "$HONEYPOT_DIR/config/honeypot.conf"

# Create systemd service file
echo -e "${YELLOW}[*] Creating systemd service...${NC}"
cat > /etc/systemd/system/honeypot.service <<EOF
[Unit]
Description=Honeypot Client Service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=${HONEYPOT_USER}
WorkingDirectory=${HONEYPOT_DIR}
ExecStart=${HONEYPOT_DIR}/venv/bin/python3 ${HONEYPOT_DIR}/client.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Download and setup client script
echo -e "${YELLOW}[*] Downloading honeypot client...${NC}"
# This would be replaced with actual download from server
# For now, we'll create a placeholder that will be replaced
cat > "$HONEYPOT_DIR/client.py" <<'CLIENTEOF'
#!/usr/bin/env python3
# Placeholder - will be replaced with actual client code
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from honeypot_client import HoneypotClient

if __name__ == "__main__":
    client = HoneypotClient()
    client.run()
CLIENTEOF

chmod +x "$HONEYPOT_DIR/client.py"

# Download honeypot_client module
echo -e "${YELLOW}[*] Downloading honeypot client module...${NC}"
curl -f -o "$HONEYPOT_DIR/honeypot_client.py" "${SERVER_URL}/honeypot/honeypot_client.py" || {
    echo -e "${RED}[!] Failed to download honeypot_client.py${NC}"
    exit 1
}
chown "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR/honeypot_client.py"
chmod 644 "$HONEYPOT_DIR/honeypot_client.py"
echo -e "${GREEN}[+] Honeypot client module downloaded${NC}"

# Enable and start service
echo -e "${YELLOW}[*] Enabling honeypot service...${NC}"
systemctl daemon-reload
systemctl enable honeypot.service

# Start the service
echo -e "${YELLOW}[*] Starting honeypot service...${NC}"
systemctl start honeypot.service

# Verify service is running
sleep 2
if systemctl is-active --quiet honeypot.service; then
    echo -e "${GREEN}[+] Honeypot service is running!${NC}"
    echo -e "${GREEN}[+] Installation completed successfully!${NC}"
    echo -e "${YELLOW}[*] View logs with: journalctl -u honeypot -f${NC}"
else
    echo -e "${RED}[!] Failed to start honeypot service${NC}"
    echo -e "${YELLOW}[*] Check logs with: journalctl -u honeypot -n 50${NC}"
    exit 1
fi
