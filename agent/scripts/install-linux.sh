#!/bin/bash
# Install netflowAgent as systemd service (run as root on Linux endpoint).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/netflowAgent"
CONFIG_DIR="/etc/netflowAgent"
LOG_DIR="/var/log/netflowAgent"
SERVICE_NAME="netflowAgent"
BINARY_SRC="$SCRIPT_DIR/netflowAgent"
CONFIG_SRC="$SCRIPT_DIR/config.toml"
UNIT_SRC="$SCRIPT_DIR/netflowAgent.service"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi

if [[ ! -f "$BINARY_SRC" ]]; then
    echo "Binary not found: $BINARY_SRC" >&2
    echo "Build on this machine first: ./build-linux.sh (from agent/scripts/ or dist/linux-x64/)" >&2
    exit 1
fi

if [[ ! -f "$CONFIG_SRC" ]]; then
    echo "Config not found: $CONFIG_SRC" >&2
    exit 1
fi

echo "Installing libpcap runtime (if needed) ..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y libpcap0.8
fi

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
install -m 755 "$BINARY_SRC" "$INSTALL_DIR/netflowAgent"
install -m 644 "$CONFIG_SRC" "$CONFIG_DIR/config.toml"

if [[ -f "$UNIT_SRC" ]]; then
    install -m 644 "$UNIT_SRC" "/etc/systemd/system/${SERVICE_NAME}.service"
else
    cat >"/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=netflowAgent NetFlow export
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/netflowAgent --config $CONFIG_DIR/config.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo ""
systemctl --no-pager status "$SERVICE_NAME" || true
echo ""
echo "Log: tail -f $LOG_DIR/agent.log"
echo "Config: $CONFIG_DIR/config.toml"
