#!/bin/bash
# Run once from the VM console on a fresh Ubuntu host.
set -euo pipefail

ANSIBLE_USER="${1:-}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi

if [[ -z "$ANSIBLE_USER" ]]; then
    echo "Usage: sudo $0 <ansible-user>" >&2
    exit 2
fi

apt-get update
apt-get install -y openssh-server python3 sudo

if ! id "$ANSIBLE_USER" >/dev/null 2>&1; then
    useradd --create-home --user-group --shell /bin/bash "$ANSIBLE_USER"
    echo "Created $ANSIBLE_USER. Set a password with: sudo passwd $ANSIBLE_USER"
fi
usermod -aG sudo "$ANSIBLE_USER"
ANSIBLE_GROUP="$(id -gn "$ANSIBLE_USER")"

if [[ -n "${ANSIBLE_SSH_PUBLIC_KEY:-}" ]]; then
    install -d -m 700 -o "$ANSIBLE_USER" -g "$ANSIBLE_GROUP" "/home/$ANSIBLE_USER/.ssh"
    printf '%s\n' "$ANSIBLE_SSH_PUBLIC_KEY" \
        >"/home/$ANSIBLE_USER/.ssh/authorized_keys"
    chown "$ANSIBLE_USER:$ANSIBLE_GROUP" "/home/$ANSIBLE_USER/.ssh/authorized_keys"
    chmod 600 "/home/$ANSIBLE_USER/.ssh/authorized_keys"

    SUDOERS_FILE="/etc/sudoers.d/90-ansible-$ANSIBLE_USER"
    printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$ANSIBLE_USER" >"$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    visudo -cf "$SUDOERS_FILE"
fi

systemctl enable --now ssh

echo "SSH bootstrap complete for $ANSIBLE_USER (sudo group)."
echo "If no public key was supplied, configure a password or authorized_keys before logout."
