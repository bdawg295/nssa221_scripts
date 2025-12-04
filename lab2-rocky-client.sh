#!/usr/bin/env bash
# lab2-rocky-client.sh
# Fully fixed version: correct detection of NetworkManager connection names

set -e

echo "=== Rocky Linux Lab 2 Client Setup (Fixed DNS v3) ==="

read -rp "Enter domain FQDN (e.g. bmw7216.com): " DOMAIN
read -rp "Enter Domain Controller IP (DNS server) (e.g. 192.168.1.2): " DCIP
read -rp "Enter domain join user (e.g. Administrator): " USER
read -rsp "Enter password for $USER: " PASS
echo

echo "[*] Detecting active NetworkManager connection..."
CON=$(nmcli -t -f NAME,DEVICE con show --active | grep -v lo | cut -d: -f1)

if [[ -z "$CON" ]]; then
    echo "ERROR: Could not detect an active network connection."
    exit 1
fi

echo "[*] Active connection detected: '$CON'"

echo "[*] Applying DNS settings BEFORE realm discover..."
nmcli connection modify "$CON" ipv4.ignore-auto-dns yes
nmcli connection modify "$CON" ipv4.dns "$DCIP"
nmcli connection up "$CON"

echo "[*] DNS is now:"
nmcli dev show | grep DNS

echo "[*] Installing packages..."
dnf install -y realmd sssd oddjob oddjob-mkhomedir adcli samba-common-tools krb5-workstation

echo "[*] Discovering the domain..."
realm discover "$DOMAIN" || { echo "Domain discovery failed — DNS still incorrect."; exit 1; }

echo "[*] Joining the domain..."
echo "$PASS" | realm join --user="$USER" "$DOMAIN"

echo "[*] Enabling SSSD + home directories..."
authselect select sssd with-mkhomedir --force
systemctl enable --now sssd

echo "[*] Testing lookup..."
id "$USER@$DOMAIN" || echo "Lookup failed — but join may still be good."

echo "[+] Rocky Linux successfully joined $DOMAIN."
