#!/bin/bash
# Remove netflowAgent systemd service (run as root).
# Add --purge to also remove all files owned by the agent.
set -euo pipefail

SERVICE_NAME="netflowAgent"
PURGE=false

case "${1:-}" in
    "")
        ;;
    --purge)
        PURGE=true
        ;;
    -h|--help)
        echo "Usage: sudo $0 [--purge]"
        echo "  --purge  also remove /opt/netflowAgent, /etc/netflowAgent and /var/log/netflowAgent"
        exit 0
        ;;
    *)
        echo "Unknown option: $1" >&2
        echo "Usage: sudo $0 [--purge]" >&2
        exit 2
        ;;
esac

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

rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true

echo "Service $SERVICE_NAME removed."
if [[ "$PURGE" == true ]]; then
    rm -rf -- /opt/netflowAgent /etc/netflowAgent /var/log/netflowAgent
    echo "Agent files and logs removed."
    echo "System dependencies kept: libpcap and Rust/build tools."
else
    echo "Files kept: /opt/netflowAgent, /etc/netflowAgent, /var/log/netflowAgent"
    echo "For a complete agent cleanup, run: sudo $0 --purge"
fi
