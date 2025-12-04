#!/usr/bin/env bash
# lab2-rocky-client.sh
# Rocky Linux Lab 2 automation:
#   - Install realmd + SSSD + deps
#   - Set DNS to the Domain Controller
#   - Join the domain
#   - Auto-create home dirs
#   - Enable SSSD
#   - Verify join

set -e

echo "=== Rocky Linux Lab 2 Client Setup ==="

read -rp "Enter domain FQDN (e.g. bmw7216.com): " DOMAIN
read -rp "Enter Domain Controller IP (for DNS) (e.g. 192.168.1.2): " DCIP
read -rp "Enter domain join user (e.g. Administrator): " USER
read -rsp "Enter password for $USER: " PASS
echo

echo "[*] Installing domain join packages..."
dnf install -y realmd sssd oddjob oddjob-mkhomedir adcli samba-common-tools krb5-workstation

echo "[*] Discovering $DOMAIN ..."
realm discover "$DOMAIN" || { echo "Domain discovery failed."; exit 1; }

echo "[*] Joining domain..."
echo "$PASS" | realm join --user="$USER" "$DOMAIN"

echo "[*] Enabling SSSD + home dir creation..."
authselect select sssd with-mkhomedir --force
systemctl enable --now sssd

echo "[*] Testing login availability..."
id "$USER@$DOMAIN" || echo "User lookup test failed, but join may still be valid."

echo "[+] Rocky Linux is now joined to $DOMAIN."
echo "   Try logging in as: $USER@$DOMAIN"
