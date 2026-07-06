#!/bin/bash
# Remove netflowAgent systemd service (run as root).
set -euo pipefail

SERVICE_NAME="netflowAgent"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi

if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl disable "$SERVICE_NAME"
fi

if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
fi

echo "Service $SERVICE_NAME removed."
echo "Files kept: /opt/netflowAgent, /etc/netflowAgent, /var/log/netflowAgent"
